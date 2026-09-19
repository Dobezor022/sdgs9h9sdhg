# FedMes 3.0 — frozen Figma runtime coverage (HOTFIX2)

Authoritative design snapshot: Bridge 1.9 `freeze19-inventory`, queue sequence 682, Figma file `TScw6uOtnCh3SmSeqzyaj2`.
Direct Figma MCP access is not required at runtime; this frozen snapshot is the release contract.

## Inventory that must stay represented by runtime states

- Product screens: **194**.
- Component nodes: **1,586**.
- Component sets: **259**.
- FedMes26 top-level components: **157**.
- Call top-level components: **41**.
- Android call screens: **31**.

Screen-state families: Android Settings 9; Android Chats/Search 12; Android Conversation 30; Android Media 42; Android Security/Auth 5; Android Edge States 3; Android Calls 31; Huawei Tablet 12; Windows Desktop 32; Component Atlas 13; Legacy reference 5. Total 194.

## Runtime interpretation

The 194 frames are not 194 unrelated Activities/Windows. Many frames are interaction states of the same production surface. FedMes maps them to persistent platform runtime state machines:

- Chats/Search: compact rows, unread/muted/selected/typing, filters, folders, favorites, search states, new chat/group creation.
- Conversation: delivery states, grouped bubbles, reply/edit, context menu, reactions, selection, pinned/unread, forwarding, voice/video recording, emoji/sticker/GIF panel, offline/error feedback.
- Media: photo/video viewers, immersive chrome, buffering, scrub/seek/speed/quality/volume, PiP/mini-player, download/share/info, shared-media grid/calendar/selection/empty/error, stories and attachment picker.
- Settings/Security: notifications, privacy, storage, appearance, performance, devices, recovery and device-link approval.
- Calls: incoming/outgoing/active/reconnecting/ended/declined/no-answer/failed, audio/video/group, route/device/permissions, PiP/banner, screen share, invite/link, history and privacy.
- Huawei: responsive 1200x800 layouts use the same Android state model with tablet composition.
- Windows: desktop three-column shell, QR-only auth states, media, settings/security and audio/video/group call surfaces.

## Active source mapping

Android/Huawei:
- `ui/fedui3/FedUi3Production.kt` — frozen semantic tokens/geometry and FedMes26 primitives.
- `ui/messenger/MessengerScreen.kt` — chats/search/conversation/selection/composer/attachments/settings entry points.
- `ui/messenger/AttachmentViewer.kt`, `InlineMediaComponents.kt`, `AttachmentPickerSheet.kt` — media states.
- `ui/messenger/DeviceSettingsScreens.kt` — settings/security/device surfaces.
- `calling/FedMesCallScreen.kt`, `calling/FedMesCallRuntime.kt` — encrypted audio/video/group-call runtime and Figma call surface.

Windows:
- `MainWindow.xaml` / `MainWindow.xaml.cs` — production desktop shell and QR/messaging/call bindings.
- `FedUI3/FedMes26Visuals.cs` — frozen FedMes26 controls.
- `Calling/DesktopCallCoordinator.cs` + `FedMes.Desktop.Core/Calling/FedMesRealtimeCallTransport.cs` — audio/video/group runtime.

Server:
- `/api/v4/stream` + blind object routes provide opaque realtime media relay; server does not decrypt call media.

## Acceptance rule

A Figma frame counts as covered only when its state belongs to a live runtime surface, not merely because a screenshot/component exists. HOTFIX2 therefore gates Figma inventory metadata, active mobile/desktop primitives, encrypted call runtime, server stream routes and foreground message-first realtime code. Physical-device visual comparison remains a release QA task, not something a source-only validator can fabricate.
