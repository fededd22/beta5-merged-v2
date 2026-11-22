"""
Approbation des appareils de l'interface web depuis Telegram (admins seulement).

Remplace la partie « telebot » du script d'origine : tout passe par le bot aiogram
existant (un seul polling pour un seul token — deux bots sur le même token
provoquent l'erreur 409 « Conflict »).

Commandes : /pending /devices /remove <id> /add_admin <id> /help
Boutons inline : ✅ accepter / ❌ refuser / 🚫 bannir sous chaque demande.
"""

import html
import os

from aiogram import types
from aiogram.filters import Command
from aiogram.types import FSInputFile, InlineKeyboardButton, InlineKeyboardMarkup

import botconfig
import registry
import runlog
import webstore
import time
from keepalive import add_log

_get_bot = lambda: None  # noqa: E731  (remplacé par register())
_admins = []


def _is_admin(user) -> bool:
    return bool(user) and user.id in _admins


def _is_main_admin(user) -> bool:
    return bool(user) and bool(_admins) and user.id == _admins[0]


def _msg_admin(message: types.Message) -> bool:
    return _is_admin(message.from_user)


def _cb_admin(call: types.CallbackQuery) -> bool:
    return _is_admin(call.from_user)


def _request_keyboard(rid: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ قبول", callback_data=f"acc_{rid}"),
         InlineKeyboardButton(text="❌ رفض", callback_data=f"rej_{rid}")],
        [InlineKeyboardButton(text="🚫 حظر", callback_data=f"blk_{rid}")],
    ])


def _request_text(req: dict, title: str) -> str:
    return (f"{title}\n\n"
            f"🆔 معرف الجهاز: <code>{html.escape(req.get('simple_id', ''))}</code>\n"
            f"🌐 IP: {html.escape(str(req.get('ip_address', '')))}\n"
            f"📋 رقم الطلب: <code>{html.escape(req.get('request_id', ''))}</code>\n"
            f"📅 التاريخ: {html.escape(str(req.get('date', ''))[:19].replace('T', ' '))}")


def pending_count() -> int:
    return len(webstore.pending_list())


async def notify_new_request(req: dict) -> None:
    """Appelée (via la boucle du bot) à chaque nouvelle demande d'accès web."""
    bot = _get_bot()
    if bot is None:
        return  # bot pas encore démarré : la demande reste visible via /pending
    text = _request_text(req, "🔔 <b>طلب وصول جديد للواجهة</b>")
    for admin_id in list(_admins):
        try:
            await bot.send_message(admin_id, text, parse_mode="HTML",
                                   reply_markup=_request_keyboard(req["request_id"]))
        except Exception as e:
            add_log(f"[WebAdmin] cannot notify admin {admin_id}: {e}")


# ==================== ÉVÉNEMENTS DE SCRIPTS ====================
_last_file_sent = {}   # (folder, fichier) -> timestamp : évite d'inonder les admins de fichiers
FILE_RESEND_AFTER_S = 60


def _event_text(ev: dict) -> str:
    blocked = ev.get("status") == "blocked"
    src = "تلغرام" if ev.get("source") == "telegram" else "الواجهة (ويب)"
    lines = ["🚫 <b>تم رفض تشغيل ملف</b>" if blocked else "▶️ <b>مستخدم شغّل ملفه</b>", "",
             f"👤 المستخدم: {html.escape(ev.get('name') or '-')}",
             f"🆔 المعرف: <code>{html.escape(str(ev.get('user_id')))}</code>",
             f"📡 المصدر: {src}",
             f"📄 الملف: <code>{html.escape(ev.get('filename', ''))}</code>",
             f"🕒 الوقت: {html.escape(ev.get('time', ''))}"]
    if ev.get("pid"):
        lines.append(f"⚙️ PID: {ev['pid']}")
    if blocked and ev.get("reasons"):
        lines.append("\n⚠️ <b>السبب:</b>\n" + "\n".join("• " + html.escape(r) for r in ev["reasons"]))
    return "\n".join(lines)[:1000]


async def notify_script_event(ev: dict, path: str) -> None:
    """Envoie aux admins le message + le fichier du script lancé (ou refusé)."""
    bot = _get_bot()
    if bot is None:
        return
    key = (ev.get("folder"), ev.get("filename"))
    blocked = ev.get("status") == "blocked"
    now = time.time()
    send_file = blocked or now - _last_file_sent.get(key, 0) > FILE_RESEND_AFTER_S
    if send_file:
        _last_file_sent[key] = now
    markup = None
    if blocked and str(ev.get("user_id")).isdigit():
        markup = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(
            text="🔒 حظر المستخدم", callback_data=f"bun_{ev['user_id']}")]])
    text = _event_text(ev)
    for admin_id in list(_admins):
        if str(admin_id) == str(ev.get("user_id")):
            continue  # l'admin n'a pas besoin d'être notifié de son propre lancement
        try:
            if send_file and path and os.path.isfile(path):
                await bot.send_document(admin_id, FSInputFile(path), caption=text,
                                        parse_mode="HTML", reply_markup=markup)
            else:
                await bot.send_message(admin_id, text, parse_mode="HTML", reply_markup=markup)
        except Exception as e:
            add_log(f"[WebAdmin] cannot send script event to {admin_id}: {e}")


async def cmd_runlog(message: types.Message):
    entries = runlog.recent(15)
    if not entries:
        await message.reply("🕒 لا يوجد سجل تشغيل بعد")
        return
    lines = ["🕒 <b>آخر عمليات التشغيل</b>", ""]
    for e in entries:
        icon = "🚫" if e["status"] == "blocked" else "▶️"
        who = html.escape(e.get("name") or e["user_id"])
        lines.append(f"{icon} {html.escape(e['time'])} — {who} (<code>{html.escape(e['user_id'])}</code>)\n"
                     f"    📄 {html.escape(e['filename'])} [{'tg' if e['source'] == 'telegram' else 'web'}]")
    await message.reply("\n".join(lines)[:4000], parse_mode="HTML")


async def cb_ban_user(call: types.CallbackQuery):
    uid = call.data[4:]
    if not uid.isdigit():
        await call.answer("❌ معرف غير صالح", show_alert=True)
        return
    registry.bot_banned.add(int(uid))
    webstore.ban(uid)
    await call.answer("🔒 تم حظر المستخدم")
    try:
        await call.message.edit_reply_markup(reply_markup=None)
    except Exception:
        pass


# ==================== COMMANDES ====================
async def cmd_pending(message: types.Message):
    pending = webstore.pending_list()
    if not pending:
        await message.reply("✅ لا توجد طلبات معلقة حالياً")
        return
    await message.reply(f"📋 عدد الطلبات المعلقة: {len(pending)}")
    for req in pending[:20]:
        await message.answer(_request_text(req, "🆔 <b>طلب معلق</b>"), parse_mode="HTML",
                             reply_markup=_request_keyboard(req["request_id"]))


async def cmd_devices(message: types.Message):
    devices = webstore.allowed_list()
    if not devices:
        await message.reply("📱 لا توجد أجهزة مسموح بها")
        return
    lines = [f"✅ الأجهزة المسموح بها ({len(devices)}):", ""]
    for i, d in enumerate(devices, 1):
        lines.append(f"{i}. <code>{html.escape(d['id'])}</code>\n    📅 {html.escape(d['added_date'] or 'غير معروف')}")
    markup = None
    if len(devices) <= 15 and _is_main_admin(message.from_user):
        markup = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=f"❌ حذف {d['id'][:8]}…", callback_data=f"rem_{d['id']}")]
            for d in devices
        ])
    await message.reply("\n".join(lines), parse_mode="HTML", reply_markup=markup)


async def cmd_remove(message: types.Message):
    if not _is_main_admin(message.from_user):
        return
    parts = (message.text or "").split(maxsplit=1)
    if len(parts) < 2:
        await message.reply("❌ استخدام: /remove [معرف_الجهاز]")
        return
    if webstore.remove_allowed(parts[1]):
        await message.reply(f"✅ تم حذف الجهاز\n📱 المتبقي: {len(webstore.allowed_list())}")
    else:
        await message.reply("❌ الجهاز غير موجود")


async def cmd_add_admin(message: types.Message):
    if not _is_main_admin(message.from_user):
        return
    parts = (message.text or "").split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip().isdigit():
        await message.reply("❌ استخدام: /add_admin [معرف_التلجرام] (أرقام فقط)")
        return
    if not botconfig.add_extra_admin(parts[1].strip()):
        await message.reply("❌ هذا المستخدم أدمن بالفعل")
        return
    _admins[:] = botconfig.get_admin_ids()
    await message.reply(f"✅ تمت إضافة الأدمن: {parts[1].strip()}\n👥 عدد المدراء: {len(_admins)}")


async def cmd_help(message: types.Message):
    await message.reply(
        "🛠️ <b>أوامر الأدمن</b>\n\n"
        "/pending - الطلبات المعلقة\n"
        "/devices - الأجهزة المسموح بها\n"
        "/remove [id] - حذف جهاز (الأدمن الرئيسي)\n"
        "/add_admin [id] - إضافة أدمن (الأدمن الرئيسي)\n"
        "/runlog - سجل تشغيل الملفات\n/status - حالة السيرفر\n\n"
        f"👥 عدد المدراء: {len(_admins)}",
        parse_mode="HTML")


# ==================== BOUTONS INLINE ====================
async def _finish(call: types.CallbackQuery, text: str, toast: str):
    try:
        await call.message.edit_text(text, parse_mode="HTML")
    except Exception:
        pass
    await call.answer(toast)


async def cb_accept(call: types.CallbackQuery):
    rid = call.data[4:]
    req = webstore.get_request(rid)
    if not req:
        await call.answer("❌ الطلب غير موجود", show_alert=True)
        return
    webstore.add_allowed(req["simple_id"])
    webstore.set_status(rid, "accepted", call.from_user.id)
    await _finish(call, _request_text(req, "✅ <b>تم قبول الطلب</b>")
                  + f"\n👤 بواسطة: {html.escape(call.from_user.first_name or '')}"
                  + f"\n📱 إجمالي الأجهزة: {len(webstore.allowed_list())}", "✅ تم القبول")


async def cb_reject(call: types.CallbackQuery):
    rid = call.data[4:]
    req = webstore.get_request(rid)
    if not req:
        await call.answer("❌ الطلب غير موجود", show_alert=True)
        return
    webstore.set_status(rid, "rejected", call.from_user.id)
    await _finish(call, _request_text(req, "❌ <b>تم رفض الطلب</b>")
                  + f"\n👤 بواسطة: {html.escape(call.from_user.first_name or '')}", "❌ تم الرفض")


async def cb_block(call: types.CallbackQuery):
    rid = call.data[4:]
    req = webstore.get_request(rid)
    if not req:
        await call.answer("❌ الطلب غير موجود", show_alert=True)
        return
    webstore.ban(req["simple_id"])
    webstore.set_status(rid, "blocked", call.from_user.id)
    await _finish(call, _request_text(req, "🚫 <b>تم حظر الجهاز</b>")
                  + f"\n🔒 المحظورون: {len(webstore.banned_list())}", "🚫 تم الحظر")


async def cb_remove(call: types.CallbackQuery):
    if not _is_main_admin(call.from_user):
        await call.answer("❌ الأدمن الرئيسي فقط", show_alert=True)
        return
    did = call.data[4:]
    if not webstore.remove_allowed(did):
        await call.answer("❌ الجهاز غير موجود", show_alert=True)
        return
    await _finish(call, f"✅ تم حذف الجهاز: <code>{html.escape(did)}</code>\n"
                        f"📱 المتبقي: {len(webstore.allowed_list())}", "✅ تم الحذف")


# ==================== ENREGISTREMENT ====================
def register(dp, admins: list, get_bot) -> None:
    """À appeler AVANT le handler « attrape-tout » du bot (l'ordre d'enregistrement compte)."""
    global _get_bot, _admins
    _get_bot, _admins = get_bot, admins

    dp.message.register(cmd_pending, Command("pending"), _msg_admin)
    dp.message.register(cmd_pending, lambda m: m.text == "📋 الطلبات المعلقة" and _msg_admin(m))
    dp.message.register(cmd_devices, Command("devices"), _msg_admin)
    dp.message.register(cmd_devices, lambda m: m.text == "📱 الأجهزة المسموح بها" and _msg_admin(m))
    dp.message.register(cmd_remove, Command("remove"), _msg_admin)
    dp.message.register(cmd_add_admin, Command("add_admin"), _msg_admin)
    dp.message.register(cmd_help, Command("help"), _msg_admin)
    dp.message.register(cmd_runlog, Command("runlog"), _msg_admin)
    dp.message.register(cmd_runlog, lambda m: m.text == "🕒 سجل التشغيل" and _msg_admin(m))

    dp.callback_query.register(cb_accept, lambda c: (c.data or "").startswith("acc_"), _cb_admin)
    dp.callback_query.register(cb_reject, lambda c: (c.data or "").startswith("rej_"), _cb_admin)
    dp.callback_query.register(cb_block, lambda c: (c.data or "").startswith("blk_"), _cb_admin)
    dp.callback_query.register(cb_ban_user, lambda c: (c.data or "").startswith("bun_"), _cb_admin)
    dp.callback_query.register(cb_remove, lambda c: (c.data or "").startswith("rem_"), _cb_admin)
