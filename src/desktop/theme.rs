use gpui::{App, Window, px, rgb};
use gpui_component::Theme;

pub(crate) fn synchronize(window: &mut Window, cx: &mut App) {
    Theme::sync_system_appearance(Some(window), cx);
    let theme = cx.global_mut::<Theme>();
    theme.radius = px(6.);
    let (accent, hover, selection) = if theme.mode.is_dark() {
        (0x85bcff, 0xa7cfff, 0x243c55)
    } else {
        (0x1756a3, 0x184a87, 0xe7f0fc)
    };
    theme.colors.primary = rgb(accent).into();
    theme.colors.primary_hover = rgb(hover).into();
    theme.colors.primary_active = theme.colors.primary_hover;
    theme.colors.primary_foreground = rgb(if theme.mode.is_dark() {
        0x0e2239
    } else {
        0xffffff
    })
    .into();
    theme.colors.progress_bar = theme.colors.primary;
    theme.colors.ring = theme.colors.primary;
    theme.colors.list_active = rgb(selection).into();
    if theme.mode.is_dark() {
        theme.colors.background = rgb(0x141a21).into();
        theme.colors.muted = rgb(0x202831).into();
        theme.colors.muted_foreground = rgb(0xaab8c8).into();
        theme.colors.border = rgb(0x374450).into();
        theme.colors.danger = rgb(0xff9294).into();
        theme.colors.success = rgb(0x57c690).into();
    } else {
        theme.colors.muted_foreground = rgb(0x586470).into();
        theme.colors.danger = rgb(0xa5212b).into();
    }
    window.refresh();
}
