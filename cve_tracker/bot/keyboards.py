"""Inline keyboards and menus for Telegram Bot."""

from telegram import InlineKeyboardButton, InlineKeyboardMarkup


def get_main_menu() -> InlineKeyboardMarkup:
    """Main navigation menu keyboard."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔍 Latest CVEs", callback_data="nav_latest"),
            InlineKeyboardButton("🔥 CISA KEV (0-Day)", callback_data="nav_cisa"),
        ],
        [
            InlineKeyboardButton("🔔 Subscribe", callback_data="nav_subscribe"),
            InlineKeyboardButton("🔕 Unsubscribe", callback_data="nav_unsubscribe"),
        ],
        [
            InlineKeyboardButton("⚙️ Filter Rules", callback_data="nav_filterlist"),
            InlineKeyboardButton("❓ Help", callback_data="nav_help"),
        ],
    ])


def get_filter_type_menu() -> InlineKeyboardMarkup:
    """Filter selection keyboard."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🏢 Vendor", callback_data="filter_add_vendor"),
            InlineKeyboardButton("📦 Product", callback_data="filter_add_product"),
        ],
        [
            InlineKeyboardButton("🔑 Keyword", callback_data="filter_add_keyword"),
            InlineKeyboardButton("🏷️ CWE", callback_data="filter_add_cwe"),
        ],
        [
            InlineKeyboardButton("🧹 Clear All Filters", callback_data="filter_clear"),
            InlineKeyboardButton("🔙 Back to Menu", callback_data="nav_menu"),
        ],
    ])
