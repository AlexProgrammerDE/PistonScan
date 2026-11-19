use gpui::{
    Context, Div, DragMoveEvent, IntoElement, MouseButton, Stateful, div, prelude::*, px,
    uniform_list,
};
use gpui_component::{
    ActiveTheme, Sizable, StyledExt,
    button::{Button, ButtonVariants},
    input::Input,
};
use pistonscan::snapshot::HostResult;

use super::{
    inspector,
    state::{self, Filter, Sort},
};
use crate::Desktop;

struct ColumnDrag;

impl Render for ColumnDrag {
    fn render(&mut self, _: &mut gpui::Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
    }
}

const ROW_HEIGHT: u16 = 58;

fn row_y(row: usize) -> gpui::Pixels {
    px(f32::from(u16::try_from(row).unwrap_or(u16::MAX)) * f32::from(ROW_HEIGHT))
}

impl Desktop {
    pub(crate) fn update_visible(&mut self, cx: &Context<Self>) {
        let query = self.search.read(cx).value().to_lowercase();
        let hosts = &self.snapshot.results;
        self.visible = hosts
            .iter()
            .enumerate()
            .filter(|(_, host)| self.filter.matches(host) && state::matches(host, &query))
            .map(|(index, _)| index)
            .collect();
        self.visible
            .sort_unstable_by(|a, b| self.sort.order(&hosts[*a], &hosts[*b]));
    }

    pub(crate) fn refresh_stream(&mut self, first_new: usize, cx: &Context<Self>) {
        let mut offset = self.scroll.0.borrow().base_handle.offset();
        let anchor = self
            .visible
            .iter()
            .enumerate()
            .find(|(row, _)| row_y(row.saturating_add(1)) > -offset.y)
            .map(|(row, index)| (row, *index));
        let query = self.search.read(cx).value().to_lowercase();
        let hosts = &self.snapshot.results;
        let previous_len = self.visible.len();
        self.visible
            .extend((first_new..hosts.len()).filter(|index| {
                self.filter.matches(&hosts[*index]) && state::matches(&hosts[*index], &query)
            }));
        if self.visible.len() == previous_len {
            return;
        }
        self.visible
            .sort_by(|a, b| self.sort.order(&hosts[*a], &hosts[*b]));
        if let Some((old_row, index)) = anchor
            && let Some(new_row) = self
                .visible
                .iter()
                .position(|candidate| *candidate == index)
        {
            offset.y += row_y(old_row) - row_y(new_row);
            self.scroll.0.borrow().base_handle.set_offset(offset);
        }
    }

    pub(crate) fn results(&self, cx: &Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let selected = self
            .selected
            .as_ref()
            .and_then(|ip| self.snapshot.results.iter().find(|host| host.ip == *ip));
        div().flex().flex_1().min_h_0()
            .child(div().flex().flex_col().flex_1().min_w_0()
                .child(div().px_5().py_3().flex().items_center().justify_between().gap_3()
                    .child(div().flex().items_center().gap_2()
                        .child(div().font_bold().child("Devices"))
                        .child(div().text_sm().text_color(theme.muted_foreground).child(self.visible.len().to_string())))
                    .child(div().w(px(240.)).child(Input::new(&self.search).small())))
                .child(div().px_5().pb_3().flex().flex_wrap().gap_2().children(
                    [("Online", Filter::Online), ("All", Filter::All), ("Has services", Filter::Services), ("Identified", Filter::Identified)]
                        .map(|(label, filter)| {
                            let button = Button::new(label).small().label(label)
                                .on_click(cx.listener(move |view, _, _, cx| {
                                    view.filter = filter;
                                    view.update_visible(cx);
                                    view.save(cx);
                                    cx.notify();
                                }));
                            if filter == self.filter {
                                button.primary()
                            } else {
                                button.outline()
                            }
                        })
                ))
                .when(self.visible.is_empty(), |view| view.child(
                    div().flex_1().flex().flex_col().justify_center().items_center().gap_2().p_5()
                        .child(div().text_2xl().font_bold().child(if self.busy() { "Finding devices" } else if self.snapshot.results.is_empty() { "See what’s on your network" } else { "No matching devices" }))
                        .child(div().text_sm().text_color(theme.muted_foreground).child(if self.busy() { "Devices appear here as they respond." } else if self.snapshot.results.is_empty() { "Scan an IPv4 subnet to find devices and see how to reach them." } else { "Try another search or filter." }))
                ))
                .when(!self.visible.is_empty(), |view| view
                    .child(div().flex().items_center().gap_2().px_5().py_1().bg(theme.muted)
                        .child(div().flex().flex_1().min_w_0().child(sort_button("Device", Sort::Name, self.sort, cx)))
                        .child(self.column(0, sort_button("IP address", Sort::Address, self.sort, cx), cx))
                        .child(self.column(1, sort_button("Latency", Sort::Latency, self.sort, cx), cx))
                        .child(self.column(2, div().text_sm().child("Services"), cx)))
                    .child(uniform_list("devices", self.visible.len(), cx.processor(|view, range: std::ops::Range<usize>, _, cx| {
                        range.map(|row| view.host_row(view.visible[row], cx)).collect()
                    })).flex_1().min_h_0().track_scroll(self.scroll.clone()))
                ))
            .when_some(selected.filter(|_| self.inspector), |view, host| view.child(
                div().id("inspector").w(px(340.)).flex_shrink_0().border_l_1().border_color(theme.border)
                    .overflow_y_scroll().child(inspector::details(host, self.raw, cx))
            ))
    }

    fn column(&self, index: usize, label: impl IntoElement, cx: &Context<Self>) -> Div {
        let width = self.columns[index];
        div()
            .flex()
            .items_center()
            .justify_between()
            .w(px(width))
            .flex_shrink_0()
            .child(label)
            .child(
                div()
                    .id(("resize-column", index))
                    .w(px(7.))
                    .h(px(22.))
                    .cursor_col_resize()
                    .hover({
                        let border = cx.theme().border;
                        move |handle| handle.bg(border)
                    })
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |view, event: &gpui::MouseDownEvent, _, _| {
                            view.resize_start = Some((event.position.x, view.columns[index]));
                        }),
                    )
                    .on_drag(index, |_, _, _, cx| cx.new(|_| ColumnDrag))
                    .on_drag_move(
                        cx.listener(move |view, event: &DragMoveEvent<usize>, _, cx| {
                            if *event.drag(cx) == index
                                && let Some((x, width)) = view.resize_start
                            {
                                let (min, max) = [(104., 130.), (82., 100.), (100., 130.)][index];
                                view.columns[index] =
                                    (width + f32::from(event.event.position.x - x)).clamp(min, max);
                                cx.notify();
                            }
                        }),
                    )
                    .on_mouse_up_out(
                        MouseButton::Left,
                        cx.listener(|view, _, _, cx| {
                            if view.resize_start.take().is_some() {
                                view.save(cx);
                            }
                        }),
                    )
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(|view, _, _, cx| {
                            if view.resize_start.take().is_some() {
                                view.save(cx);
                            }
                        }),
                    ),
            )
    }

    fn host_row(&self, index: usize, cx: &Context<Self>) -> Stateful<Div> {
        let host = &self.snapshot.results[index];
        let theme = cx.theme();
        let ip = host.ip.clone();
        let icon = device_icon(host);
        div()
            .id(gpui::SharedString::from(ip.clone()))
            .w_full()
            .flex()
            .items_center()
            .gap_2()
            .px_5()
            .h(row_y(1))
            .border_b_1()
            .border_color(theme.border)
            .cursor_pointer()
            .hover(|row| row.bg(theme.muted))
            .when(
                host.reachable && self.latest.is_some_and(|(first, _)| index >= first),
                |row| row.bg(theme.muted),
            )
            .when(self.selected.as_ref() == Some(&ip), |row| {
                row.bg(theme.list_active)
            })
            .on_click(cx.listener(move |view, _, window, cx| {
                window.focus(&view.focus);
                view.selected = Some(ip.clone());
                view.inspector = true;
                view.raw = false;
                cx.notify();
            }))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .flex_1()
                    .min_w_0()
                    .child(div().size(px(6.)).flex_shrink_0().rounded_full().bg(
                        if host.reachable {
                            theme.success
                        } else {
                            theme.muted_foreground
                        },
                    ))
                    .child(gpui_component::Icon::new(icon).size_4().flex_shrink_0())
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .truncate()
                                    .font_bold()
                                    .child(state::name(host).to_owned()),
                            )
                            .child(
                                div()
                                    .truncate()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .child(
                                        [host.manufacturer.as_str(), host.os_guess.as_str()]
                                            .into_iter()
                                            .filter(|value| {
                                                !value.is_empty() && *value != "Unknown"
                                            })
                                            .collect::<Vec<_>>()
                                            .join(" / "),
                                    ),
                            ),
                    ),
            )
            .child(
                div()
                    .w(px(self.columns[0]))
                    .flex_shrink_0()
                    .truncate()
                    .text_sm()
                    .child(host.ip.clone()),
            )
            .child(
                div()
                    .w(px(self.columns[1]))
                    .flex_shrink_0()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child(if host.reachable {
                        format!("{:.1} ms", host.latency_ms)
                    } else {
                        "Offline".into()
                    }),
            )
            .child(service_chips(host, self.columns[2], cx))
    }
}

fn service_chips(host: &HostResult, width: f32, cx: &Context<Desktop>) -> Div {
    let service_count = host.services.len();
    div()
        .flex()
        .gap_1()
        .w(px(width))
        .flex_shrink_0()
        .min_w_0()
        .overflow_hidden()
        .children(
            host.services
                .first()
                .map(|service| chip(service.service.clone(), cx)),
        )
        .when(service_count > 1, |row| {
            row.child(chip(format!("+{}", service_count - 1), cx))
        })
}

fn chip(label: String, cx: &Context<Desktop>) -> Div {
    div()
        .min_w_0()
        .truncate()
        .px_2()
        .py_1()
        .rounded_md()
        .text_xs()
        .bg(cx.theme().muted)
        .child(label)
}

fn sort_button(label: &'static str, sort: Sort, current: Sort, cx: &Context<Desktop>) -> Button {
    Button::new(label)
        .small()
        .ghost()
        .px_0()
        .label(if current == sort {
            format!("{label} ↑")
        } else {
            label.to_owned()
        })
        .tooltip(format!("Sort by {}", label.to_lowercase()))
        .on_click(cx.listener(move |view, _, _, cx| {
            view.sort = sort;
            view.update_visible(cx);
            view.save(cx);
            cx.notify();
        }))
}

fn device_icon(host: &HostResult) -> gpui_component::IconName {
    use gpui_component::IconName;
    let name = state::name(host).to_lowercase();
    if name.contains("router") || name.contains("gateway") {
        IconName::Globe
    } else if name.contains("phone") {
        IconName::User
    } else if name.contains("printer") {
        IconName::File
    } else if name.contains(" tv") || host.air_play.is_some() {
        IconName::LayoutDashboard
    } else if name.contains("sensor") {
        IconName::Bot
    } else if name.contains("nas") || name.contains("server") {
        IconName::Building2
    } else if name == "unknown device" {
        IconName::Info
    } else {
        IconName::Frame
    }
}
