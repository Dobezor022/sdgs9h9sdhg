# FedMes 3.0 — Figma Bridge 1.9 implementation matrix

Source of truth: `FedMes 2.0.1 — Messenger UI`, Bridge 1.9 freeze `freeze19-inventory`, Google Sheet sequence 682.

Inventory frozen for the 3.0 source release:

| Figma area | Screens |
|---|---:|
| Android · Settings | 9 |
| Android · Chats & Search | 12 |
| Android · Conversation | 30 |
| Android · Media | 42 |
| Android · Security & Auth | 5 |
| Android · Edge States | 3 |
| Android · Calls | 31 |
| Huawei Tablet | 12 |
| Windows Desktop | 32 |
| Component Atlas | 13 |
| Legacy Screens | 5 |
| **Product screens total** | **194** |

Design-system inventory: 1,586 component nodes, 290 top-level components, 259 component sets, 157 FedMes26 top-level components, 41 call top-level components.

## Frozen semantic contract

Dark: `#0E1621` background, `#17212B` surface, `#202B36` raised, `#2B3A48` border, `#F4F7FA` primary text, `#8E9DAA` secondary text, `#3390EC` accent, `#182533` incoming bubble, `#2B5278` outgoing bubble. Light: `#F4F7FA` background, `#FFFFFF` surface, `#EDF2F6` raised, `#DCE5EC` border, `#17212B` primary text, `#70808D` secondary text, `#3390EC` accent, `#FFFFFF` incoming bubble and final overridden `#E1FFC7` outgoing bubble.

Geometry used by runtime surfaces: Android reference 390×844, compact chat row 68, avatar 54, top bar 58, bottom navigation 72, composer 54, selected radius 14, active navigation radius 20, media player reference 390×520, call control tray 390×104 / radius 26.

## Runtime mapping

| Figma family | Android / Huawei | Windows | Runtime status in 3.0 source |
|---|---|---|---|
| Chat list / compact rows / unread / typing / selected | `ui/fedui3/FedUi3Production.kt` + active `MessengerScreen.kt` | active `MainWindow.xaml` + `FedUI3/FedMes26Visuals.cs` | Integrated |
| Bottom navigation / search / profile / settings destinations | active `MessengerScreen.kt` | desktop navigation remains desktop-specific | Integrated on mobile; desktop uses its Figma desktop shell |
| Text/photo/file/audio/video/round messages | existing encrypted messenger runtime + 3.0 tokens | existing encrypted messenger runtime + 3.0 tokens | Integrated; exact rendering remains platform-native where appropriate |
| Media viewer/player | existing Media3/viewer runtime + FedMes26 chrome primitives | existing `MediaPlayerWindow` + FedMes26 video chrome primitive | Runtime exists; device visual QA required |
| Settings / appearance / privacy / storage / devices / recovery | existing screens with 3.0 theme contract | existing settings/security windows with 3.0 theme contract | Integrated |
| QR-only desktop authentication / device approval | existing QR/device-link implementation | existing QR sign-in implementation | Integrated; password/legacy OPAQUE stays fail-closed |
| Huawei tablet | same Android binary with responsive Compose runtime | n/a | Source-compatible; 1200×800 device QA required |
| Calls / group calls / screen-share | `FedMesCallScreen` + `FedMesCallRuntime` + FedMes26 call states | `DesktopCallCoordinator` + encrypted realtime transport + FedMes26 controls | **Runtime implemented over blind encrypted realtime stream; physical multi-device QA remains required** |
| Story/reactions/folders/advanced atlas surfaces | underlying messaging/media actions exist where already implemented | desktop equivalents where already implemented | Figma inventory retained as source-of-truth; not every one of 194 presentation frames is a separate runtime screen class |

## Production rule

A Figma presentation frame is not counted as a runtime feature merely because a matching frame exists. Release acceptance requires: source validation, platform compilation, API/schema tests, QR/E2EE regression tests, and physical-device QA for Android/Huawei/Windows. The 3.0 ZIP contains the code and build/install pipeline; it does not pretend that an unavailable SDK or unexecuted device test passed.


HOTFIX2 runtime coverage contract: `docs/FIGMA-RUNTIME-COVERAGE-HOTFIX2.md`.
