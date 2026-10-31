# Lucide Animated Icon Catalog & Integration Guide

> Complete reference directory for 468+ motion-backed Lucide icons from [lucide-animated.com](https://lucide-animated.com/).
> Handcrafted micro-interactions powered by `motion` (Framer Motion) and compatible with `shadcn/ui`.

---

## 1. Quick Start in Any React / Next.js Project

### Step 1: Install Motion
```bash
npm install motion
```

### Step 2: Configure Registry in `components.json`
Add the `@lucide-animated` registry to your project `components.json` file:
```json
{
  "registries": {
    "@lucide-animated": "https://lucide-animated.com/r/{name}.json"
  }
}
```

### Step 3: Add Icons via shadcn CLI
```bash
# Add a single icon:
npx shadcn add @lucide-animated/shield-check

# Add multiple icons at once:
npx shadcn add @lucide-animated/sparkles @lucide-animated/refresh-cw @lucide-animated/terminal
```

---

## 2. Component Usage & Best Practices

### Basic Usage
```tsx
import { ShieldCheckIcon } from "@/components/ui/shield-check";

export function MyComponent() {
  return (
    <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg border">
      <ShieldCheckIcon size={18} className="text-emerald-500" />
      <span>Verified Safe</span>
    </button>
  );
}
```

### Imperative Animation Control (via Ref)
Each component exposes a ref handle allowing you to trigger or cancel animations programmatically (e.g., on parent hover, tap, or state change):
```tsx
import { useRef } from "react";
import { SparklesIcon, type SparklesIconHandle } from "@/components/ui/sparkles";

export function ActionButton() {
  const iconRef = useRef<SparklesIconHandle>(null);

  return (
    <div
      onMouseEnter={() => iconRef.current?.startAnimation()}
      onMouseLeave={() => iconRef.current?.stopAnimation()}
      className="card p-4 hover:shadow-lg"
    >
      <SparklesIcon ref={iconRef} size={24} />
      <span>Hover the entire card to trigger</span>
    </div>
  );
}
```

### Bulletproof Sizing & Styling Pattern
`lucide-animated` renders an outer `<div>` around the SVG. To make it behave identically to standard inline SVGs in all CSS layouts, apply:
```tsx
className="inline-flex items-center justify-center shrink-0 [&>svg]:w-full [&>svg]:h-full"
```

---

## 3. Categorized Icon Directory (468 Icons)

### Arrows & Navigation (58 icons)

| Icon Name (Kebab) | Component Export | shadcn CLI Command |
| :--- | :--- | :--- |
| `a-arrow-down` | `AArrowDownIcon` | `npx shadcn add @lucide-animated/a-arrow-down` |
| `a-arrow-up` | `AArrowUpIcon` | `npx shadcn add @lucide-animated/a-arrow-up` |
| `arrow-big-down` | `ArrowBigDownIcon` | `npx shadcn add @lucide-animated/arrow-big-down` |
| `arrow-big-down-dash` | `ArrowBigDownDashIcon` | `npx shadcn add @lucide-animated/arrow-big-down-dash` |
| `arrow-big-left` | `ArrowBigLeftIcon` | `npx shadcn add @lucide-animated/arrow-big-left` |
| `arrow-big-left-dash` | `ArrowBigLeftDashIcon` | `npx shadcn add @lucide-animated/arrow-big-left-dash` |
| `arrow-big-right` | `ArrowBigRightIcon` | `npx shadcn add @lucide-animated/arrow-big-right` |
| `arrow-big-right-dash` | `ArrowBigRightDashIcon` | `npx shadcn add @lucide-animated/arrow-big-right-dash` |
| `arrow-big-up` | `ArrowBigUpIcon` | `npx shadcn add @lucide-animated/arrow-big-up` |
| `arrow-big-up-dash` | `ArrowBigUpDashIcon` | `npx shadcn add @lucide-animated/arrow-big-up-dash` |
| `arrow-down` | `ArrowDownIcon` | `npx shadcn add @lucide-animated/arrow-down` |
| `arrow-down-0-1` | `ArrowDown01Icon` | `npx shadcn add @lucide-animated/arrow-down-0-1` |
| `arrow-down-1-0` | `ArrowDown10Icon` | `npx shadcn add @lucide-animated/arrow-down-1-0` |
| `arrow-down-a-z` | `ArrowDownAZIcon` | `npx shadcn add @lucide-animated/arrow-down-a-z` |
| `arrow-down-left` | `ArrowDownLeftIcon` | `npx shadcn add @lucide-animated/arrow-down-left` |
| `arrow-down-right` | `ArrowDownRightIcon` | `npx shadcn add @lucide-animated/arrow-down-right` |
| `arrow-down-z-a` | `ArrowDownZAIcon` | `npx shadcn add @lucide-animated/arrow-down-z-a` |
| `arrow-left` | `ArrowLeftIcon` | `npx shadcn add @lucide-animated/arrow-left` |
| `arrow-right` | `ArrowRightIcon` | `npx shadcn add @lucide-animated/arrow-right` |
| `arrow-up` | `ArrowUpIcon` | `npx shadcn add @lucide-animated/arrow-up` |
| `arrow-up-left` | `ArrowUpLeftIcon` | `npx shadcn add @lucide-animated/arrow-up-left` |
| `arrow-up-right` | `ArrowUpRightIcon` | `npx shadcn add @lucide-animated/arrow-up-right` |
| `chevron-down` | `ChevronDownIcon` | `npx shadcn add @lucide-animated/chevron-down` |
| `chevron-first` | `ChevronFirstIcon` | `npx shadcn add @lucide-animated/chevron-first` |
| `chevron-left` | `ChevronLeftIcon` | `npx shadcn add @lucide-animated/chevron-left` |
| `chevron-right` | `ChevronRightIcon` | `npx shadcn add @lucide-animated/chevron-right` |
| `chevron-up` | `ChevronUpIcon` | `npx shadcn add @lucide-animated/chevron-up` |
| `chevrons-down-up` | `ChevronsDownUpIcon` | `npx shadcn add @lucide-animated/chevrons-down-up` |
| `chevrons-left-right` | `ChevronsLeftRightIcon` | `npx shadcn add @lucide-animated/chevrons-left-right` |
| `chevrons-right-left` | `ChevronsRightLeftIcon` | `npx shadcn add @lucide-animated/chevrons-right-left` |
| `chevrons-up-down` | `ChevronsUpDownIcon` | `npx shadcn add @lucide-animated/chevrons-up-down` |
| `circle-chevron-down` | `CircleChevronDownIcon` | `npx shadcn add @lucide-animated/circle-chevron-down` |
| `circle-chevron-left` | `CircleChevronLeftIcon` | `npx shadcn add @lucide-animated/circle-chevron-left` |
| `circle-chevron-right` | `CircleChevronRightIcon` | `npx shadcn add @lucide-animated/circle-chevron-right` |
| `circle-chevron-up` | `CircleChevronUpIcon` | `npx shadcn add @lucide-animated/circle-chevron-up` |
| `corner-down-left` | `CornerDownLeftIcon` | `npx shadcn add @lucide-animated/corner-down-left` |
| `corner-down-right` | `CornerDownRightIcon` | `npx shadcn add @lucide-animated/corner-down-right` |
| `corner-left-down` | `CornerLeftDownIcon` | `npx shadcn add @lucide-animated/corner-left-down` |
| `corner-left-up` | `CornerLeftUpIcon` | `npx shadcn add @lucide-animated/corner-left-up` |
| `corner-right-down` | `CornerRightDownIcon` | `npx shadcn add @lucide-animated/corner-right-down` |
| `corner-right-up` | `CornerRightUpIcon` | `npx shadcn add @lucide-animated/corner-right-up` |
| `corner-up-left` | `CornerUpLeftIcon` | `npx shadcn add @lucide-animated/corner-up-left` |
| `corner-up-right` | `CornerUpRightIcon` | `npx shadcn add @lucide-animated/corner-up-right` |
| `git-compare-arrows` | `GitCompareArrowsIcon` | `npx shadcn add @lucide-animated/git-compare-arrows` |
| `route` | `RouteIcon` | `npx shadcn add @lucide-animated/route` |
| `router` | `RouterIcon` | `npx shadcn add @lucide-animated/router` |
| `square-arrow-down` | `SquareArrowDownIcon` | `npx shadcn add @lucide-animated/square-arrow-down` |
| `square-arrow-left` | `SquareArrowLeftIcon` | `npx shadcn add @lucide-animated/square-arrow-left` |
| `square-arrow-right` | `SquareArrowRightIcon` | `npx shadcn add @lucide-animated/square-arrow-right` |
| `square-arrow-up` | `SquareArrowUpIcon` | `npx shadcn add @lucide-animated/square-arrow-up` |
| `square-chevron-down` | `SquareChevronDownIcon` | `npx shadcn add @lucide-animated/square-chevron-down` |
| `square-chevron-left` | `SquareChevronLeftIcon` | `npx shadcn add @lucide-animated/square-chevron-left` |
| `square-chevron-right` | `SquareChevronRightIcon` | `npx shadcn add @lucide-animated/square-chevron-right` |
| `square-chevron-up` | `SquareChevronUpIcon` | `npx shadcn add @lucide-animated/square-chevron-up` |
| `waves-arrow-down` | `WavesArrowDownIcon` | `npx shadcn add @lucide-animated/waves-arrow-down` |
| `waves-arrow-up` | `WavesArrowUpIcon` | `npx shadcn add @lucide-animated/waves-arrow-up` |
| `waypoints` | `WaypointsIcon` | `npx shadcn add @lucide-animated/waypoints` |
| `wind-arrow-down` | `WindArrowDownIcon` | `npx shadcn add @lucide-animated/wind-arrow-down` |

### Security, Privacy & Badges (22 icons)

| Icon Name (Kebab) | Component Export | shadcn CLI Command |
| :--- | :--- | :--- |
| `alarm-clock` | `AlarmClockIcon` | `npx shadcn add @lucide-animated/alarm-clock` |
| `alarm-clock-check` | `AlarmClockCheckIcon` | `npx shadcn add @lucide-animated/alarm-clock-check` |
| `alarm-clock-minus` | `AlarmClockMinusIcon` | `npx shadcn add @lucide-animated/alarm-clock-minus` |
| `alarm-clock-plus` | `AlarmClockPlusIcon` | `npx shadcn add @lucide-animated/alarm-clock-plus` |
| `badge-alert` | `BadgeAlertIcon` | `npx shadcn add @lucide-animated/badge-alert` |
| `badge-percent` | `BadgePercentIcon` | `npx shadcn add @lucide-animated/badge-percent` |
| `blocks` | `BlocksIcon` | `npx shadcn add @lucide-animated/blocks` |
| `clock` | `ClockIcon` | `npx shadcn add @lucide-animated/clock` |
| `fingerprint` | `FingerprintIcon` | `npx shadcn add @lucide-animated/fingerprint` |
| `folder-clock` | `FolderClockIcon` | `npx shadcn add @lucide-animated/folder-clock` |
| `folder-key` | `FolderKeyIcon` | `npx shadcn add @lucide-animated/folder-key` |
| `folder-lock` | `FolderLockIcon` | `npx shadcn add @lucide-animated/folder-lock` |
| `key` | `KeyIcon` | `npx shadcn add @lucide-animated/key` |
| `key-circle` | `KeyCircleIcon` | `npx shadcn add @lucide-animated/key-circle` |
| `key-square` | `KeySquareIcon` | `npx shadcn add @lucide-animated/key-square` |
| `keyboard` | `KeyboardIcon` | `npx shadcn add @lucide-animated/keyboard` |
| `lock` | `LockIcon` | `npx shadcn add @lucide-animated/lock` |
| `lock-keyhole` | `LockKeyholeIcon` | `npx shadcn add @lucide-animated/lock-keyhole` |
| `lock-keyhole-open` | `LockKeyholeOpenIcon` | `npx shadcn add @lucide-animated/lock-keyhole-open` |
| `lock-open` | `LockOpenIcon` | `npx shadcn add @lucide-animated/lock-open` |
| `scan-face` | `ScanFaceIcon` | `npx shadcn add @lucide-animated/scan-face` |
| `shield-check` | `ShieldCheckIcon` | `npx shadcn add @lucide-animated/shield-check` |

### Development, Git & Terminal (19 icons)

| Icon Name (Kebab) | Component Export | shadcn CLI Command |
| :--- | :--- | :--- |
| `binary` | `BinaryIcon` | `npx shadcn add @lucide-animated/binary` |
| `folder-code` | `FolderCodeIcon` | `npx shadcn add @lucide-animated/folder-code` |
| `folder-git` | `FolderGitIcon` | `npx shadcn add @lucide-animated/folder-git` |
| `folder-git-2` | `FolderGit2Icon` | `npx shadcn add @lucide-animated/folder-git-2` |
| `git-branch` | `GitBranchIcon` | `npx shadcn add @lucide-animated/git-branch` |
| `git-commit-horizontal` | `GitCommitHorizontalIcon` | `npx shadcn add @lucide-animated/git-commit-horizontal` |
| `git-commit-vertical` | `GitCommitVerticalIcon` | `npx shadcn add @lucide-animated/git-commit-vertical` |
| `git-compare` | `GitCompareIcon` | `npx shadcn add @lucide-animated/git-compare` |
| `git-fork` | `GitForkIcon` | `npx shadcn add @lucide-animated/git-fork` |
| `git-graph` | `GitGraphIcon` | `npx shadcn add @lucide-animated/git-graph` |
| `git-merge` | `GitMergeIcon` | `npx shadcn add @lucide-animated/git-merge` |
| `git-pull-request` | `GitPullRequestIcon` | `npx shadcn add @lucide-animated/git-pull-request` |
| `git-pull-request-closed` | `GitPullRequestClosedIcon` | `npx shadcn add @lucide-animated/git-pull-request-closed` |
| `git-pull-request-create` | `GitPullRequestCreateIcon` | `npx shadcn add @lucide-animated/git-pull-request-create` |
| `github` | `GithubIcon` | `npx shadcn add @lucide-animated/github` |
| `gitlab` | `GitlabIcon` | `npx shadcn add @lucide-animated/gitlab` |
| `terminal` | `TerminalIcon` | `npx shadcn add @lucide-animated/terminal` |
| `webhook` | `WebhookIcon` | `npx shadcn add @lucide-animated/webhook` |
| `workflow` | `WorkflowIcon` | `npx shadcn add @lucide-animated/workflow` |

### Files, Folders & Documents (35 icons)

| Icon Name (Kebab) | Component Export | shadcn CLI Command |
| :--- | :--- | :--- |
| `archive` | `ArchiveIcon` | `npx shadcn add @lucide-animated/archive` |
| `attach-file` | `AttachFileIcon` | `npx shadcn add @lucide-animated/attach-file` |
| `book-text` | `BookTextIcon` | `npx shadcn add @lucide-animated/book-text` |
| `bookmark` | `BookmarkIcon` | `npx shadcn add @lucide-animated/bookmark` |
| `bookmark-check` | `BookmarkCheckIcon` | `npx shadcn add @lucide-animated/bookmark-check` |
| `bookmark-minus` | `BookmarkMinusIcon` | `npx shadcn add @lucide-animated/bookmark-minus` |
| `bookmark-plus` | `BookmarkPlusIcon` | `npx shadcn add @lucide-animated/bookmark-plus` |
| `bookmark-x` | `BookmarkXIcon` | `npx shadcn add @lucide-animated/bookmark-x` |
| `clipboard-check` | `ClipboardCheckIcon` | `npx shadcn add @lucide-animated/clipboard-check` |
| `facebook` | `FacebookIcon` | `npx shadcn add @lucide-animated/facebook` |
| `file-chart-line` | `FileChartLineIcon` | `npx shadcn add @lucide-animated/file-chart-line` |
| `file-check` | `FileCheckIcon` | `npx shadcn add @lucide-animated/file-check` |
| `file-check-2` | `FileCheck2Icon` | `npx shadcn add @lucide-animated/file-check-2` |
| `file-cog` | `FileCogIcon` | `npx shadcn add @lucide-animated/file-cog` |
| `file-pen-line` | `FilePenLineIcon` | `npx shadcn add @lucide-animated/file-pen-line` |
| `file-stack` | `FileStackIcon` | `npx shadcn add @lucide-animated/file-stack` |
| `file-text` | `FileTextIcon` | `npx shadcn add @lucide-animated/file-text` |
| `folder-archive` | `FolderArchiveIcon` | `npx shadcn add @lucide-animated/folder-archive` |
| `folder-check` | `FolderCheckIcon` | `npx shadcn add @lucide-animated/folder-check` |
| `folder-cog` | `FolderCogIcon` | `npx shadcn add @lucide-animated/folder-cog` |
| `folder-dot` | `FolderDotIcon` | `npx shadcn add @lucide-animated/folder-dot` |
| `folder-down` | `FolderDownIcon` | `npx shadcn add @lucide-animated/folder-down` |
| `folder-heart` | `FolderHeartIcon` | `npx shadcn add @lucide-animated/folder-heart` |
| `folder-input` | `FolderInputIcon` | `npx shadcn add @lucide-animated/folder-input` |
| `folder-kanban` | `FolderKanbanIcon` | `npx shadcn add @lucide-animated/folder-kanban` |
| `folder-minus` | `FolderMinusIcon` | `npx shadcn add @lucide-animated/folder-minus` |
| `folder-open` | `FolderOpenIcon` | `npx shadcn add @lucide-animated/folder-open` |
| `folder-output` | `FolderOutputIcon` | `npx shadcn add @lucide-animated/folder-output` |
| `folder-plus` | `FolderPlusIcon` | `npx shadcn add @lucide-animated/folder-plus` |
| `folder-root` | `FolderRootIcon` | `npx shadcn add @lucide-animated/folder-root` |
| `folder-sync` | `FolderSyncIcon` | `npx shadcn add @lucide-animated/folder-sync` |
| `folder-tree` | `FolderTreeIcon` | `npx shadcn add @lucide-animated/folder-tree` |
| `folder-up` | `FolderUpIcon` | `npx shadcn add @lucide-animated/folder-up` |
| `folder-x` | `FolderXIcon` | `npx shadcn add @lucide-animated/folder-x` |
| `folders` | `FoldersIcon` | `npx shadcn add @lucide-animated/folders` |

### Charts, Analytics & Data (17 icons)

| Icon Name (Kebab) | Component Export | shadcn CLI Command |
| :--- | :--- | :--- |
| `activity` | `ActivityIcon` | `npx shadcn add @lucide-animated/activity` |
| `chart-bar-decreasing` | `ChartBarDecreasingIcon` | `npx shadcn add @lucide-animated/chart-bar-decreasing` |
| `chart-bar-increasing` | `ChartBarIncreasingIcon` | `npx shadcn add @lucide-animated/chart-bar-increasing` |
| `chart-column-decreasing` | `ChartColumnDecreasingIcon` | `npx shadcn add @lucide-animated/chart-column-decreasing` |
| `chart-column-increasing` | `ChartColumnIncreasingIcon` | `npx shadcn add @lucide-animated/chart-column-increasing` |
| `chart-line` | `ChartLineIcon` | `npx shadcn add @lucide-animated/chart-line` |
| `chart-no-axes-column-decreasing` | `ChartNoAxesColumnDecreasingIcon` | `npx shadcn add @lucide-animated/chart-no-axes-column-decreasing` |
| `chart-no-axes-column-increasing` | `ChartNoAxesColumnIncreasingIcon` | `npx shadcn add @lucide-animated/chart-no-axes-column-increasing` |
| `chart-pie` | `ChartPieIcon` | `npx shadcn add @lucide-animated/chart-pie` |
| `chart-scatter` | `ChartScatterIcon` | `npx shadcn add @lucide-animated/chart-scatter` |
| `chart-spline` | `ChartSplineIcon` | `npx shadcn add @lucide-animated/chart-spline` |
| `circle-gauge` | `CircleGaugeIcon` | `npx shadcn add @lucide-animated/circle-gauge` |
| `gauge` | `GaugeIcon` | `npx shadcn add @lucide-animated/gauge` |
| `square-activity` | `SquareActivityIcon` | `npx shadcn add @lucide-animated/square-activity` |
| `trending-down` | `TrendingDownIcon` | `npx shadcn add @lucide-animated/trending-down` |
| `trending-up` | `TrendingUpIcon` | `npx shadcn add @lucide-animated/trending-up` |
| `trending-up-down` | `TrendingUpDownIcon` | `npx shadcn add @lucide-animated/trending-up-down` |

### Actions, Controls & Editing (54 icons)

| Icon Name (Kebab) | Component Export | shadcn CLI Command |
| :--- | :--- | :--- |
| `battery-plus` | `BatteryPlusIcon` | `npx shadcn add @lucide-animated/battery-plus` |
| `bluetooth-searching` | `BluetoothSearchingIcon` | `npx shadcn add @lucide-animated/bluetooth-searching` |
| `calendar-check` | `CalendarCheckIcon` | `npx shadcn add @lucide-animated/calendar-check` |
| `calendar-check-2` | `CalendarCheck2Icon` | `npx shadcn add @lucide-animated/calendar-check-2` |
| `check` | `CheckIcon` | `npx shadcn add @lucide-animated/check` |
| `check-check` | `CheckCheckIcon` | `npx shadcn add @lucide-animated/check-check` |
| `circle-check` | `CircleCheckIcon` | `npx shadcn add @lucide-animated/circle-check` |
| `cloud-download` | `CloudDownloadIcon` | `npx shadcn add @lucide-animated/cloud-download` |
| `cloud-upload` | `CloudUploadIcon` | `npx shadcn add @lucide-animated/cloud-upload` |
| `copy` | `CopyIcon` | `npx shadcn add @lucide-animated/copy` |
| `credit-card` | `CreditCardIcon` | `npx shadcn add @lucide-animated/credit-card` |
| `delete` | `DeleteIcon` | `npx shadcn add @lucide-animated/delete` |
| `download` | `DownloadIcon` | `npx shadcn add @lucide-animated/download` |
| `hammer` | `HammerIcon` | `npx shadcn add @lucide-animated/hammer` |
| `hard-drive-download` | `HardDriveDownloadIcon` | `npx shadcn add @lucide-animated/hard-drive-download` |
| `hard-drive-upload` | `HardDriveUploadIcon` | `npx shadcn add @lucide-animated/hard-drive-upload` |
| `laptop-minimal-check` | `LaptopMinimalCheckIcon` | `npx shadcn add @lucide-animated/laptop-minimal-check` |
| `mail-check` | `MailCheckIcon` | `npx shadcn add @lucide-animated/mail-check` |
| `map-pin-check` | `MapPinCheckIcon` | `npx shadcn add @lucide-animated/map-pin-check` |
| `map-pin-check-inside` | `MapPinCheckInsideIcon` | `npx shadcn add @lucide-animated/map-pin-check-inside` |
| `map-pin-minus` | `MapPinMinusIcon` | `npx shadcn add @lucide-animated/map-pin-minus` |
| `map-pin-minus-inside` | `MapPinMinusInsideIcon` | `npx shadcn add @lucide-animated/map-pin-minus-inside` |
| `map-pin-plus` | `MapPinPlusIcon` | `npx shadcn add @lucide-animated/map-pin-plus` |
| `map-pin-plus-inside` | `MapPinPlusInsideIcon` | `npx shadcn add @lucide-animated/map-pin-plus-inside` |
| `message-circle-check` | `MessageCircleCheckIcon` | `npx shadcn add @lucide-animated/message-circle-check` |
| `message-circle-plus` | `MessageCirclePlusIcon` | `npx shadcn add @lucide-animated/message-circle-plus` |
| `message-square-check` | `MessageSquareCheckIcon` | `npx shadcn add @lucide-animated/message-square-check` |
| `message-square-plus` | `MessageSquarePlusIcon` | `npx shadcn add @lucide-animated/message-square-plus` |
| `monitor-check` | `MonitorCheckIcon` | `npx shadcn add @lucide-animated/monitor-check` |
| `panel-left-open` | `PanelLeftOpenIcon` | `npx shadcn add @lucide-animated/panel-left-open` |
| `panel-right-open` | `PanelRightOpenIcon` | `npx shadcn add @lucide-animated/panel-right-open` |
| `pen-tool` | `PenToolIcon` | `npx shadcn add @lucide-animated/pen-tool` |
| `plus` | `PlusIcon` | `npx shadcn add @lucide-animated/plus` |
| `redo` | `RedoIcon` | `npx shadcn add @lucide-animated/redo` |
| `redo-dot` | `RedoDotIcon` | `npx shadcn add @lucide-animated/redo-dot` |
| `refresh-ccw` | `RefreshCcwIcon` | `npx shadcn add @lucide-animated/refresh-ccw` |
| `refresh-ccw-dot` | `RefreshCcwDotIcon` | `npx shadcn add @lucide-animated/refresh-ccw-dot` |
| `refresh-cw` | `RefreshCwIcon` | `npx shadcn add @lucide-animated/refresh-cw` |
| `refresh-cw-off` | `RefreshCwOffIcon` | `npx shadcn add @lucide-animated/refresh-cw-off` |
| `rotate-ccw` | `RotateCcwIcon` | `npx shadcn add @lucide-animated/rotate-ccw` |
| `rotate-cw` | `RotateCwIcon` | `npx shadcn add @lucide-animated/rotate-cw` |
| `search` | `SearchIcon` | `npx shadcn add @lucide-animated/search` |
| `sliders-horizontal` | `SlidersHorizontalIcon` | `npx shadcn add @lucide-animated/sliders-horizontal` |
| `smile-plus` | `SmilePlusIcon` | `npx shadcn add @lucide-animated/smile-plus` |
| `square-pen` | `SquarePenIcon` | `npx shadcn add @lucide-animated/square-pen` |
| `undo` | `UndoIcon` | `npx shadcn add @lucide-animated/undo` |
| `undo-dot` | `UndoDotIcon` | `npx shadcn add @lucide-animated/undo-dot` |
| `upload` | `UploadIcon` | `npx shadcn add @lucide-animated/upload` |
| `user-check` | `UserCheckIcon` | `npx shadcn add @lucide-animated/user-check` |
| `user-plus` | `UserPlusIcon` | `npx shadcn add @lucide-animated/user-plus` |
| `user-round-check` | `UserRoundCheckIcon` | `npx shadcn add @lucide-animated/user-round-check` |
| `user-round-plus` | `UserRoundPlusIcon` | `npx shadcn add @lucide-animated/user-round-plus` |
| `wifi-pen` | `WifiPenIcon` | `npx shadcn add @lucide-animated/wifi-pen` |
| `wrench` | `WrenchIcon` | `npx shadcn add @lucide-animated/wrench` |

### Media, Theme & Environment (25 icons)

| Icon Name (Kebab) | Component Export | shadcn CLI Command |
| :--- | :--- | :--- |
| `brain` | `BrainIcon` | `npx shadcn add @lucide-animated/brain` |
| `cloud-backup` | `CloudBackupIcon` | `npx shadcn add @lucide-animated/cloud-backup` |
| `cloud-cog` | `CloudCogIcon` | `npx shadcn add @lucide-animated/cloud-cog` |
| `cloud-lightning` | `CloudLightningIcon` | `npx shadcn add @lucide-animated/cloud-lightning` |
| `cloud-rain` | `CloudRainIcon` | `npx shadcn add @lucide-animated/cloud-rain` |
| `cloud-rain-wind` | `CloudRainWindIcon` | `npx shadcn add @lucide-animated/cloud-rain-wind` |
| `cloud-snow` | `CloudSnowIcon` | `npx shadcn add @lucide-animated/cloud-snow` |
| `cloud-sun` | `CloudSunIcon` | `npx shadcn add @lucide-animated/cloud-sun` |
| `cloud-sync` | `CloudSyncIcon` | `npx shadcn add @lucide-animated/cloud-sync` |
| `droplet` | `DropletIcon` | `npx shadcn add @lucide-animated/droplet` |
| `flame` | `FlameIcon` | `npx shadcn add @lucide-animated/flame` |
| `leaf` | `LeafIcon` | `npx shadcn add @lucide-animated/leaf` |
| `leafy-green` | `LeafyGreenIcon` | `npx shadcn add @lucide-animated/leafy-green` |
| `moon` | `MoonIcon` | `npx shadcn add @lucide-animated/moon` |
| `snowflake` | `SnowflakeIcon` | `npx shadcn add @lucide-animated/snowflake` |
| `sparkles` | `SparklesIcon` | `npx shadcn add @lucide-animated/sparkles` |
| `sun` | `SunIcon` | `npx shadcn add @lucide-animated/sun` |
| `sun-dim` | `SunDimIcon` | `npx shadcn add @lucide-animated/sun-dim` |
| `sun-medium` | `SunMediumIcon` | `npx shadcn add @lucide-animated/sun-medium` |
| `sun-moon` | `SunMoonIcon` | `npx shadcn add @lucide-animated/sun-moon` |
| `sunset` | `SunsetIcon` | `npx shadcn add @lucide-animated/sunset` |
| `train-track` | `TrainTrackIcon` | `npx shadcn add @lucide-animated/train-track` |
| `tree-deciduous` | `TreeDeciduousIcon` | `npx shadcn add @lucide-animated/tree-deciduous` |
| `tree-pine` | `TreePineIcon` | `npx shadcn add @lucide-animated/tree-pine` |
| `wind` | `WindIcon` | `npx shadcn add @lucide-animated/wind` |

### Devices, Hardware & Connectivity (24 icons)

| Icon Name (Kebab) | Component Export | shadcn CLI Command |
| :--- | :--- | :--- |
| `battery` | `BatteryIcon` | `npx shadcn add @lucide-animated/battery` |
| `battery-charging` | `BatteryChargingIcon` | `npx shadcn add @lucide-animated/battery-charging` |
| `battery-full` | `BatteryFullIcon` | `npx shadcn add @lucide-animated/battery-full` |
| `battery-low` | `BatteryLowIcon` | `npx shadcn add @lucide-animated/battery-low` |
| `battery-medium` | `BatteryMediumIcon` | `npx shadcn add @lucide-animated/battery-medium` |
| `battery-warning` | `BatteryWarningIcon` | `npx shadcn add @lucide-animated/battery-warning` |
| `bluetooth` | `BluetoothIcon` | `npx shadcn add @lucide-animated/bluetooth` |
| `bluetooth-connected` | `BluetoothConnectedIcon` | `npx shadcn add @lucide-animated/bluetooth-connected` |
| `bluetooth-off` | `BluetoothOffIcon` | `npx shadcn add @lucide-animated/bluetooth-off` |
| `cctv` | `CctvIcon` | `npx shadcn add @lucide-animated/cctv` |
| `cpu` | `CpuIcon` | `npx shadcn add @lucide-animated/cpu` |
| `monitor-cog` | `MonitorCogIcon` | `npx shadcn add @lucide-animated/monitor-cog` |
| `projector` | `ProjectorIcon` | `npx shadcn add @lucide-animated/projector` |
| `radio` | `RadioIcon` | `npx shadcn add @lucide-animated/radio` |
| `radio-tower` | `RadioTowerIcon` | `npx shadcn add @lucide-animated/radio-tower` |
| `server` | `ServerIcon` | `npx shadcn add @lucide-animated/server` |
| `server-cog` | `ServerCogIcon` | `npx shadcn add @lucide-animated/server-cog` |
| `server-crash` | `ServerCrashIcon` | `npx shadcn add @lucide-animated/server-crash` |
| `smartphone-charging` | `SmartphoneChargingIcon` | `npx shadcn add @lucide-animated/smartphone-charging` |
| `smartphone-nfc` | `SmartphoneNfcIcon` | `npx shadcn add @lucide-animated/smartphone-nfc` |
| `wifi` | `WifiIcon` | `npx shadcn add @lucide-animated/wifi` |
| `wifi-cog` | `WifiCogIcon` | `npx shadcn add @lucide-animated/wifi-cog` |
| `wifi-low` | `WifiLowIcon` | `npx shadcn add @lucide-animated/wifi-low` |
| `wifi-sync` | `WifiSyncIcon` | `npx shadcn add @lucide-animated/wifi-sync` |

### Communication & Social (28 icons)

| Icon Name (Kebab) | Component Export | shadcn CLI Command |
| :--- | :--- | :--- |
| `bell` | `BellIcon` | `npx shadcn add @lucide-animated/bell` |
| `bell-electric` | `BellElectricIcon` | `npx shadcn add @lucide-animated/bell-electric` |
| `bot-message-square` | `BotMessageSquareIcon` | `npx shadcn add @lucide-animated/bot-message-square` |
| `concierge-bell` | `ConciergeBellIcon` | `npx shadcn add @lucide-animated/concierge-bell` |
| `discord` | `DiscordIcon` | `npx shadcn add @lucide-animated/discord` |
| `instagram` | `InstagramIcon` | `npx shadcn add @lucide-animated/instagram` |
| `linkedin` | `LinkedinIcon` | `npx shadcn add @lucide-animated/linkedin` |
| `mailbox` | `MailboxIcon` | `npx shadcn add @lucide-animated/mailbox` |
| `message-circle` | `MessageCircleIcon` | `npx shadcn add @lucide-animated/message-circle` |
| `message-circle-dashed` | `MessageCircleDashedIcon` | `npx shadcn add @lucide-animated/message-circle-dashed` |
| `message-circle-more` | `MessageCircleMoreIcon` | `npx shadcn add @lucide-animated/message-circle-more` |
| `message-circle-x` | `MessageCircleXIcon` | `npx shadcn add @lucide-animated/message-circle-x` |
| `message-square` | `MessageSquareIcon` | `npx shadcn add @lucide-animated/message-square` |
| `message-square-dashed` | `MessageSquareDashedIcon` | `npx shadcn add @lucide-animated/message-square-dashed` |
| `message-square-more` | `MessageSquareMoreIcon` | `npx shadcn add @lucide-animated/message-square-more` |
| `message-square-x` | `MessageSquareXIcon` | `npx shadcn add @lucide-animated/message-square-x` |
| `mic` | `MicIcon` | `npx shadcn add @lucide-animated/mic` |
| `mic-off` | `MicOffIcon` | `npx shadcn add @lucide-animated/mic-off` |
| `phone` | `PhoneIcon` | `npx shadcn add @lucide-animated/phone` |
| `phone-call` | `PhoneCallIcon` | `npx shadcn add @lucide-animated/phone-call` |
| `phone-forwarded` | `PhoneForwardedIcon` | `npx shadcn add @lucide-animated/phone-forwarded` |
| `phone-incoming` | `PhoneIncomingIcon` | `npx shadcn add @lucide-animated/phone-incoming` |
| `phone-missed` | `PhoneMissedIcon` | `npx shadcn add @lucide-animated/phone-missed` |
| `phone-off` | `PhoneOffIcon` | `npx shadcn add @lucide-animated/phone-off` |
| `send` | `SendIcon` | `npx shadcn add @lucide-animated/send` |
| `twitch` | `TwitchIcon` | `npx shadcn add @lucide-animated/twitch` |
| `twitter` | `TwitterIcon` | `npx shadcn add @lucide-animated/twitter` |
| `youtube` | `YoutubeIcon` | `npx shadcn add @lucide-animated/youtube` |

### Commerce, Currency & Finance (24 icons)

| Icon Name (Kebab) | Component Export | shadcn CLI Command |
| :--- | :--- | :--- |
| `cart` | `CartIcon` | `npx shadcn add @lucide-animated/cart` |
| `circle-dollar-sign` | `CircleDollarSignIcon` | `npx shadcn add @lucide-animated/circle-dollar-sign` |
| `dollar-sign` | `DollarSignIcon` | `npx shadcn add @lucide-animated/dollar-sign` |
| `euro` | `EuroIcon` | `npx shadcn add @lucide-animated/euro` |
| `georgian-lari` | `GeorgianLariIcon` | `npx shadcn add @lucide-animated/georgian-lari` |
| `indian-rupee` | `IndianRupeeIcon` | `npx shadcn add @lucide-animated/indian-rupee` |
| `japanese-yen` | `JapaneseYenIcon` | `npx shadcn add @lucide-animated/japanese-yen` |
| `philippine-peso` | `PhilippinePesoIcon` | `npx shadcn add @lucide-animated/philippine-peso` |
| `pound-sterling` | `PoundSterlingIcon` | `npx shadcn add @lucide-animated/pound-sterling` |
| `receipt` | `ReceiptIcon` | `npx shadcn add @lucide-animated/receipt` |
| `receipt-cent` | `ReceiptCentIcon` | `npx shadcn add @lucide-animated/receipt-cent` |
| `receipt-euro` | `ReceiptEuroIcon` | `npx shadcn add @lucide-animated/receipt-euro` |
| `receipt-indian-rupee` | `ReceiptIndianRupeeIcon` | `npx shadcn add @lucide-animated/receipt-indian-rupee` |
| `receipt-japanese-yen` | `ReceiptJapaneseYenIcon` | `npx shadcn add @lucide-animated/receipt-japanese-yen` |
| `receipt-pound-sterling` | `ReceiptPoundSterlingIcon` | `npx shadcn add @lucide-animated/receipt-pound-sterling` |
| `receipt-russian-ruble` | `ReceiptRussianRubleIcon` | `npx shadcn add @lucide-animated/receipt-russian-ruble` |
| `receipt-swiss-franc` | `ReceiptSwissFrancIcon` | `npx shadcn add @lucide-animated/receipt-swiss-franc` |
| `receipt-text` | `ReceiptTextIcon` | `npx shadcn add @lucide-animated/receipt-text` |
| `receipt-turkish-lira` | `ReceiptTurkishLiraIcon` | `npx shadcn add @lucide-animated/receipt-turkish-lira` |
| `russian-ruble` | `RussianRubleIcon` | `npx shadcn add @lucide-animated/russian-ruble` |
| `saudi-riyal` | `SaudiRiyalIcon` | `npx shadcn add @lucide-animated/saudi-riyal` |
| `swiss-franc` | `SwissFrancIcon` | `npx shadcn add @lucide-animated/swiss-franc` |
| `turkish-lira` | `TurkishLiraIcon` | `npx shadcn add @lucide-animated/turkish-lira` |
| `wallet` | `WalletIcon` | `npx shadcn add @lucide-animated/wallet` |

### People, Users & Gestures (22 icons)

| Icon Name (Kebab) | Component Export | shadcn CLI Command |
| :--- | :--- | :--- |
| `angry` | `AngryIcon` | `npx shadcn add @lucide-animated/angry` |
| `annoyed` | `AnnoyedIcon` | `npx shadcn add @lucide-animated/annoyed` |
| `biceps-flexed` | `BicepsFlexedIcon` | `npx shadcn add @lucide-animated/biceps-flexed` |
| `clap` | `ClapIcon` | `npx shadcn add @lucide-animated/clap` |
| `frown` | `FrownIcon` | `npx shadcn add @lucide-animated/frown` |
| `hand` | `HandIcon` | `npx shadcn add @lucide-animated/hand` |
| `hand-coins` | `HandCoinsIcon` | `npx shadcn add @lucide-animated/hand-coins` |
| `hand-fist` | `HandFistIcon` | `npx shadcn add @lucide-animated/hand-fist` |
| `hand-grab` | `HandGrabIcon` | `npx shadcn add @lucide-animated/hand-grab` |
| `hand-heart` | `HandHeartIcon` | `npx shadcn add @lucide-animated/hand-heart` |
| `hand-helping` | `HandHelpingIcon` | `npx shadcn add @lucide-animated/hand-helping` |
| `hand-metal` | `HandMetalIcon` | `npx shadcn add @lucide-animated/hand-metal` |
| `heart` | `HeartIcon` | `npx shadcn add @lucide-animated/heart` |
| `heart-handshake` | `HeartHandshakeIcon` | `npx shadcn add @lucide-animated/heart-handshake` |
| `heart-pulse` | `HeartPulseIcon` | `npx shadcn add @lucide-animated/heart-pulse` |
| `laugh` | `LaughIcon` | `npx shadcn add @lucide-animated/laugh` |
| `meh` | `MehIcon` | `npx shadcn add @lucide-animated/meh` |
| `smile` | `SmileIcon` | `npx shadcn add @lucide-animated/smile` |
| `user` | `UserIcon` | `npx shadcn add @lucide-animated/user` |
| `user-round-cog` | `UserRoundCogIcon` | `npx shadcn add @lucide-animated/user-round-cog` |
| `users` | `UsersIcon` | `npx shadcn add @lucide-animated/users` |
| `users-round` | `UsersRoundIcon` | `npx shadcn add @lucide-animated/users-round` |

### System, Interface & Status (16 icons)

| Icon Name (Kebab) | Component Export | shadcn CLI Command |
| :--- | :--- | :--- |
| `airplay` | `AirplayIcon` | `npx shadcn add @lucide-animated/airplay` |
| `expand` | `ExpandIcon` | `npx shadcn add @lucide-animated/expand` |
| `frame` | `FrameIcon` | `npx shadcn add @lucide-animated/frame` |
| `layers` | `LayersIcon` | `npx shadcn add @lucide-animated/layers` |
| `layout-grid` | `LayoutGridIcon` | `npx shadcn add @lucide-animated/layout-grid` |
| `layout-panel-top` | `LayoutPanelTopIcon` | `npx shadcn add @lucide-animated/layout-panel-top` |
| `loader` | `LoaderIcon` | `npx shadcn add @lucide-animated/loader` |
| `loader-circle` | `LoaderCircleIcon` | `npx shadcn add @lucide-animated/loader-circle` |
| `loader-pinwheel` | `LoaderPinwheelIcon` | `npx shadcn add @lucide-animated/loader-pinwheel` |
| `maximize` | `MaximizeIcon` | `npx shadcn add @lucide-animated/maximize` |
| `maximize-2` | `Maximize2Icon` | `npx shadcn add @lucide-animated/maximize-2` |
| `menu` | `MenuIcon` | `npx shadcn add @lucide-animated/menu` |
| `minimize` | `MinimizeIcon` | `npx shadcn add @lucide-animated/minimize` |
| `pause` | `PauseIcon` | `npx shadcn add @lucide-animated/pause` |
| `play` | `PlayIcon` | `npx shadcn add @lucide-animated/play` |
| `shrink` | `ShrinkIcon` | `npx shadcn add @lucide-animated/shrink` |

### Miscellaneous & Objects (124 icons)

| Icon Name (Kebab) | Component Export | shadcn CLI Command |
| :--- | :--- | :--- |
| `accessibility` | `AccessibilityIcon` | `npx shadcn add @lucide-animated/accessibility` |
| `air-vent` | `AirVentIcon` | `npx shadcn add @lucide-animated/air-vent` |
| `airplane` | `AirplaneIcon` | `npx shadcn add @lucide-animated/airplane` |
| `alarm-smoke` | `AlarmSmokeIcon` | `npx shadcn add @lucide-animated/alarm-smoke` |
| `align-center` | `AlignCenterIcon` | `npx shadcn add @lucide-animated/align-center` |
| `align-horizontal` | `AlignHorizontalIcon` | `npx shadcn add @lucide-animated/align-horizontal` |
| `align-left` | `AlignLeftIcon` | `npx shadcn add @lucide-animated/align-left` |
| `align-right` | `AlignRightIcon` | `npx shadcn add @lucide-animated/align-right` |
| `align-vertical` | `AlignVerticalIcon` | `npx shadcn add @lucide-animated/align-vertical` |
| `ambulance` | `AmbulanceIcon` | `npx shadcn add @lucide-animated/ambulance` |
| `at-sign` | `AtSignIcon` | `npx shadcn add @lucide-animated/at-sign` |
| `atom` | `AtomIcon` | `npx shadcn add @lucide-animated/atom` |
| `audio-lines` | `AudioLinesIcon` | `npx shadcn add @lucide-animated/audio-lines` |
| `axe` | `AxeIcon` | `npx shadcn add @lucide-animated/axe` |
| `ban` | `BanIcon` | `npx shadcn add @lucide-animated/ban` |
| `banana` | `BananaIcon` | `npx shadcn add @lucide-animated/banana` |
| `bold` | `BoldIcon` | `npx shadcn add @lucide-animated/bold` |
| `bone` | `BoneIcon` | `npx shadcn add @lucide-animated/bone` |
| `bot` | `BotIcon` | `npx shadcn add @lucide-animated/bot` |
| `box` | `BoxIcon` | `npx shadcn add @lucide-animated/box` |
| `boxes` | `BoxesIcon` | `npx shadcn add @lucide-animated/boxes` |
| `briefcase-business` | `BriefcaseBusinessIcon` | `npx shadcn add @lucide-animated/briefcase-business` |
| `calendar-cog` | `CalendarCogIcon` | `npx shadcn add @lucide-animated/calendar-cog` |
| `calendar-days` | `CalendarDaysIcon` | `npx shadcn add @lucide-animated/calendar-days` |
| `car` | `CarIcon` | `npx shadcn add @lucide-animated/car` |
| `cast` | `CastIcon` | `npx shadcn add @lucide-animated/cast` |
| `chess-bishop` | `ChessBishopIcon` | `npx shadcn add @lucide-animated/chess-bishop` |
| `chess-king` | `ChessKingIcon` | `npx shadcn add @lucide-animated/chess-king` |
| `chess-knight` | `ChessKnightIcon` | `npx shadcn add @lucide-animated/chess-knight` |
| `chess-pawn` | `ChessPawnIcon` | `npx shadcn add @lucide-animated/chess-pawn` |
| `chrome` | `ChromeIcon` | `npx shadcn add @lucide-animated/chrome` |
| `cigarette` | `CigaretteIcon` | `npx shadcn add @lucide-animated/cigarette` |
| `cigarette-off` | `CigaretteOffIcon` | `npx shadcn add @lucide-animated/cigarette-off` |
| `circle-dashed` | `CircleDashedIcon` | `npx shadcn add @lucide-animated/circle-dashed` |
| `circle-help` | `CircleHelpIcon` | `npx shadcn add @lucide-animated/circle-help` |
| `coffee` | `CoffeeIcon` | `npx shadcn add @lucide-animated/coffee` |
| `cog` | `CogIcon` | `npx shadcn add @lucide-animated/cog` |
| `compass` | `CompassIcon` | `npx shadcn add @lucide-animated/compass` |
| `connect` | `ConnectIcon` | `npx shadcn add @lucide-animated/connect` |
| `construction` | `ConstructionIcon` | `npx shadcn add @lucide-animated/construction` |
| `contrast` | `ContrastIcon` | `npx shadcn add @lucide-animated/contrast` |
| `cooking-pot` | `CookingPotIcon` | `npx shadcn add @lucide-animated/cooking-pot` |
| `cup-soda` | `CupSodaIcon` | `npx shadcn add @lucide-animated/cup-soda` |
| `cursor-click` | `CursorClickIcon` | `npx shadcn add @lucide-animated/cursor-click` |
| `database-backup` | `DatabaseBackupIcon` | `npx shadcn add @lucide-animated/database-backup` |
| `disc-3` | `Disc3Icon` | `npx shadcn add @lucide-animated/disc-3` |
| `downvote` | `DownvoteIcon` | `npx shadcn add @lucide-animated/downvote` |
| `dribbble` | `DribbbleIcon` | `npx shadcn add @lucide-animated/dribbble` |
| `drum` | `DrumIcon` | `npx shadcn add @lucide-animated/drum` |
| `earth` | `EarthIcon` | `npx shadcn add @lucide-animated/earth` |
| `ev-charger` | `EvChargerIcon` | `npx shadcn add @lucide-animated/ev-charger` |
| `external-link` | `ExternalLinkIcon` | `npx shadcn add @lucide-animated/external-link` |
| `eye` | `EyeIcon` | `npx shadcn add @lucide-animated/eye` |
| `eye-off` | `EyeOffIcon` | `npx shadcn add @lucide-animated/eye-off` |
| `fan` | `FanIcon` | `npx shadcn add @lucide-animated/fan` |
| `feather` | `FeatherIcon` | `npx shadcn add @lucide-animated/feather` |
| `figma` | `FigmaIcon` | `npx shadcn add @lucide-animated/figma` |
| `fish-symbol` | `FishSymbolIcon` | `npx shadcn add @lucide-animated/fish-symbol` |
| `flask` | `FlaskIcon` | `npx shadcn add @lucide-animated/flask` |
| `gallery-horizontal-end` | `GalleryHorizontalEndIcon` | `npx shadcn add @lucide-animated/gallery-horizontal-end` |
| `gallery-thumbnails` | `GalleryThumbnailsIcon` | `npx shadcn add @lucide-animated/gallery-thumbnails` |
| `gallery-vertical-end` | `GalleryVerticalEndIcon` | `npx shadcn add @lucide-animated/gallery-vertical-end` |
| `gavel` | `GavelIcon` | `npx shadcn add @lucide-animated/gavel` |
| `graduation-cap` | `GraduationCapIcon` | `npx shadcn add @lucide-animated/graduation-cap` |
| `grip` | `GripIcon` | `npx shadcn add @lucide-animated/grip` |
| `grip-horizontal` | `GripHorizontalIcon` | `npx shadcn add @lucide-animated/grip-horizontal` |
| `grip-vertical` | `GripVerticalIcon` | `npx shadcn add @lucide-animated/grip-vertical` |
| `hat-glasses` | `HatGlassesIcon` | `npx shadcn add @lucide-animated/hat-glasses` |
| `history` | `HistoryIcon` | `npx shadcn add @lucide-animated/history` |
| `home` | `HomeIcon` | `npx shadcn add @lucide-animated/home` |
| `hourglass` | `HourglassIcon` | `npx shadcn add @lucide-animated/hourglass` |
| `id-card` | `IdCardIcon` | `npx shadcn add @lucide-animated/id-card` |
| `italic` | `ItalicIcon` | `npx shadcn add @lucide-animated/italic` |
| `languages` | `LanguagesIcon` | `npx shadcn add @lucide-animated/languages` |
| `link` | `LinkIcon` | `npx shadcn add @lucide-animated/link` |
| `link-2` | `Link2Icon` | `npx shadcn add @lucide-animated/link-2` |
| `login` | `LoginIcon` | `npx shadcn add @lucide-animated/login` |
| `logout` | `LogoutIcon` | `npx shadcn add @lucide-animated/logout` |
| `map-pin` | `MapPinIcon` | `npx shadcn add @lucide-animated/map-pin` |
| `map-pin-house` | `MapPinHouseIcon` | `npx shadcn add @lucide-animated/map-pin-house` |
| `map-pin-off` | `MapPinOffIcon` | `npx shadcn add @lucide-animated/map-pin-off` |
| `map-pin-x-inside` | `MapPinXInsideIcon` | `npx shadcn add @lucide-animated/map-pin-x-inside` |
| `nfc` | `NfcIcon` | `npx shadcn add @lucide-animated/nfc` |
| `palette` | `PaletteIcon` | `npx shadcn add @lucide-animated/palette` |
| `panel-left-close` | `PanelLeftCloseIcon` | `npx shadcn add @lucide-animated/panel-left-close` |
| `party-popper` | `PartyPopperIcon` | `npx shadcn add @lucide-animated/party-popper` |
| `pickaxe` | `PickaxeIcon` | `npx shadcn add @lucide-animated/pickaxe` |
| `plane-landing` | `PlaneLandingIcon` | `npx shadcn add @lucide-animated/plane-landing` |
| `plane-takeoff` | `PlaneTakeoffIcon` | `npx shadcn add @lucide-animated/plane-takeoff` |
| `plug-zap` | `PlugZapIcon` | `npx shadcn add @lucide-animated/plug-zap` |
| `rabbit` | `RabbitIcon` | `npx shadcn add @lucide-animated/rabbit` |
| `rocket` | `RocketIcon` | `npx shadcn add @lucide-animated/rocket` |
| `rocking-chair` | `RockingChairIcon` | `npx shadcn add @lucide-animated/rocking-chair` |
| `roller-coaster` | `RollerCoasterIcon` | `npx shadcn add @lucide-animated/roller-coaster` |
| `satellite-dish` | `SatelliteDishIcon` | `npx shadcn add @lucide-animated/satellite-dish` |
| `scan-text` | `ScanTextIcon` | `npx shadcn add @lucide-animated/scan-text` |
| `settings` | `SettingsIcon` | `npx shadcn add @lucide-animated/settings` |
| `ship` | `ShipIcon` | `npx shadcn add @lucide-animated/ship` |
| `ship-wheel` | `ShipWheelIcon` | `npx shadcn add @lucide-animated/ship-wheel` |
| `shower-head` | `ShowerHeadIcon` | `npx shadcn add @lucide-animated/shower-head` |
| `shredder` | `ShredderIcon` | `npx shadcn add @lucide-animated/shredder` |
| `soup` | `SoupIcon` | `npx shadcn add @lucide-animated/soup` |
| `spray-can` | `SprayCanIcon` | `npx shadcn add @lucide-animated/spray-can` |
| `square-stack` | `SquareStackIcon` | `npx shadcn add @lucide-animated/square-stack` |
| `stamp` | `StampIcon` | `npx shadcn add @lucide-animated/stamp` |
| `stethoscope` | `StethoscopeIcon` | `npx shadcn add @lucide-animated/stethoscope` |
| `switch-camera` | `SwitchCameraIcon` | `npx shadcn add @lucide-animated/switch-camera` |
| `syringe` | `SyringeIcon` | `npx shadcn add @lucide-animated/syringe` |
| `telescope` | `TelescopeIcon` | `npx shadcn add @lucide-animated/telescope` |
| `thermometer` | `ThermometerIcon` | `npx shadcn add @lucide-animated/thermometer` |
| `ticket` | `TicketIcon` | `npx shadcn add @lucide-animated/ticket` |
| `timer` | `TimerIcon` | `npx shadcn add @lucide-animated/timer` |
| `tornado` | `TornadoIcon` | `npx shadcn add @lucide-animated/tornado` |
| `truck` | `TruckIcon` | `npx shadcn add @lucide-animated/truck` |
| `underline` | `UnderlineIcon` | `npx shadcn add @lucide-animated/underline` |
| `upvote` | `UpvoteIcon` | `npx shadcn add @lucide-animated/upvote` |
| `vibrate` | `VibrateIcon` | `npx shadcn add @lucide-animated/vibrate` |
| `volume` | `VolumeIcon` | `npx shadcn add @lucide-animated/volume` |
| `washing-machine` | `WashingMachineIcon` | `npx shadcn add @lucide-animated/washing-machine` |
| `waves` | `WavesIcon` | `npx shadcn add @lucide-animated/waves` |
| `waves-ladder` | `WavesLadderIcon` | `npx shadcn add @lucide-animated/waves-ladder` |
| `x` | `XIcon` | `npx shadcn add @lucide-animated/x` |
| `zap` | `ZapIcon` | `npx shadcn add @lucide-animated/zap` |
| `zap-off` | `ZapOffIcon` | `npx shadcn add @lucide-animated/zap-off` |

---

## 4. Summary of Architecture in Guardian

In this project, we wrapped these icons into a unified barrel file at `@/components/icons`:
- Provides both PascalCase handles (`ShieldCheckIcon`) and drop-in Lucide aliases (`ShieldCheck`, `CheckCircle2`, `Sparkles`, `Package`, `Terminal`, etc.).
- Automatically standardizes `inline-flex` container styling, responsive scaling, and forwards `size` / `className` props.
- Keeps high-density table views and continuous scanning spinners (`Loader2`) performant while giving all interactive touchpoints fluid hover animations.
