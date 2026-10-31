"use client";

import React, { forwardRef } from "react";
import { cn } from "@/lib/utils";

// --- Base Animated Icons imported from components/ui ---
import { ActivityIcon as BaseActivity } from "@/components/ui/activity";
import { ArrowDown01Icon as BaseArrowDown01 } from "@/components/ui/arrow-down-0-1";
import { ArrowLeftIcon as BaseArrowLeft } from "@/components/ui/arrow-left";
import { ArrowRightIcon as BaseArrowRight } from "@/components/ui/arrow-right";
import { ArrowUpIcon as BaseArrowUp } from "@/components/ui/arrow-up";
import { ArrowUpRightIcon as BaseArrowUpRight } from "@/components/ui/arrow-up-right";
import { BookTextIcon as BaseBookText } from "@/components/ui/book-text";
import { BoxIcon as BaseBox } from "@/components/ui/box";
import { CheckIcon as BaseCheck } from "@/components/ui/check";
import { ChevronDownIcon as BaseChevronDown } from "@/components/ui/chevron-down";
import { ChevronRightIcon as BaseChevronRight } from "@/components/ui/chevron-right";
import { CircleCheckIcon as BaseCircleCheck } from "@/components/ui/circle-check";
import { CircleHelpIcon as BaseCircleHelp } from "@/components/ui/circle-help";
import { ClockIcon as BaseClock } from "@/components/ui/clock";
import { CopyIcon as BaseCopy } from "@/components/ui/copy";
import { CpuIcon as BaseCpu } from "@/components/ui/cpu";
import { DownloadIcon as BaseDownload } from "@/components/ui/download";
import { ExternalLinkIcon as BaseExternalLink } from "@/components/ui/external-link";
import { EyeIcon as BaseEye } from "@/components/ui/eye";
import { FileTextIcon as BaseFileText } from "@/components/ui/file-text";
import { FlaskIcon as BaseFlask } from "@/components/ui/flask";
import { FolderGit2Icon as BaseFolderGit2 } from "@/components/ui/folder-git-2";
import { FolderOpenIcon as BaseFolderOpen } from "@/components/ui/folder-open";
import { FolderSyncIcon as BaseFolderSync } from "@/components/ui/folder-sync";
import { GitBranchIcon as BaseGitBranch } from "@/components/ui/git-branch";
import { GitPullRequestIcon as BaseGitPullRequest } from "@/components/ui/git-pull-request";
import { HistoryIcon as BaseHistory } from "@/components/ui/history";
import { LayersIcon as BaseLayers } from "@/components/ui/layers";
import { LayoutPanelTopIcon as BaseLayoutPanelTop } from "@/components/ui/layout-panel-top";
import { LockIcon as BaseLock } from "@/components/ui/lock";
import { LogoutIcon as BaseLogout } from "@/components/ui/logout";
import { Maximize2Icon as BaseMaximize2 } from "@/components/ui/maximize-2";
import { MenuIcon as BaseMenu } from "@/components/ui/menu";
import { MinimizeIcon as BaseMinimize } from "@/components/ui/minimize";
import { MoonIcon as BaseMoon } from "@/components/ui/moon";
import { PlusIcon as BasePlus } from "@/components/ui/plus";
import { RefreshCWIcon as BaseRefreshCw } from "@/components/ui/refresh-cw";
import { RotateCCWIcon as BaseRotateCcw } from "@/components/ui/rotate-ccw";
import { SearchIcon as BaseSearch } from "@/components/ui/search";
import { ShieldCheckIcon as BaseShieldCheck } from "@/components/ui/shield-check";
import { SlidersHorizontalIcon as BaseSlidersHorizontal } from "@/components/ui/sliders-horizontal";
import { SparklesIcon as BaseSparkles } from "@/components/ui/sparkles";
import { SunIcon as BaseSun } from "@/components/ui/sun";
import { TerminalIcon as BaseTerminal } from "@/components/ui/terminal";
import { TrendingDownIcon as BaseTrendingDown } from "@/components/ui/trending-down";
import { TrendingUpIcon as BaseTrendingUp } from "@/components/ui/trending-up";
import { UploadIcon as BaseUpload } from "@/components/ui/upload";
import { WrenchIcon as BaseWrench } from "@/components/ui/wrench";
import { XIcon as BaseX } from "@/components/ui/x";

export interface AnimatedIconProps extends React.HTMLAttributes<HTMLDivElement> {
  size?: number | string;
  strokeWidth?: number | string;
}

export function createAnimatedIcon(
  BaseComponent: React.ComponentType<any>,
  displayName: string
) {
  const Component = forwardRef<HTMLDivElement, AnimatedIconProps>(
    ({ size, className, style, ...props }, ref) => {
      const numericSize =
        typeof size === "number"
          ? size
          : typeof size === "string" && !isNaN(Number(size))
          ? Number(size)
          : undefined;

      const sizeStyle = numericSize
        ? { width: numericSize, height: numericSize }
        : undefined;

      return (
        <BaseComponent
          ref={ref}
          size={numericSize}
          className={cn(
            "inline-flex items-center justify-center shrink-0 [&>svg]:w-full [&>svg]:h-full",
            className
          )}
          style={{ ...sizeStyle, ...style }}
          {...props}
        />
      );
    }
  );

  Component.displayName = displayName;
  return Component;
}

// --- Wrapped Animated Icons (Primary) ---
export const ActivityIcon = createAnimatedIcon(BaseActivity, "ActivityIcon");
export const ArrowDown01Icon = createAnimatedIcon(BaseArrowDown01, "ArrowDown01Icon");
export const ArrowLeftIcon = createAnimatedIcon(BaseArrowLeft, "ArrowLeftIcon");
export const ArrowRightIcon = createAnimatedIcon(BaseArrowRight, "ArrowRightIcon");
export const ArrowUpIcon = createAnimatedIcon(BaseArrowUp, "ArrowUpIcon");
export const ArrowUpRightIcon = createAnimatedIcon(BaseArrowUpRight, "ArrowUpRightIcon");
export const BookTextIcon = createAnimatedIcon(BaseBookText, "BookTextIcon");
export const BoxIcon = createAnimatedIcon(BaseBox, "BoxIcon");
export const CheckIcon = createAnimatedIcon(BaseCheck, "CheckIcon");
export const ChevronDownIcon = createAnimatedIcon(BaseChevronDown, "ChevronDownIcon");
export const ChevronRightIcon = createAnimatedIcon(BaseChevronRight, "ChevronRightIcon");
export const CircleCheckIcon = createAnimatedIcon(BaseCircleCheck, "CircleCheckIcon");
export const CircleHelpIcon = createAnimatedIcon(BaseCircleHelp, "CircleHelpIcon");
export const ClockIcon = createAnimatedIcon(BaseClock, "ClockIcon");
export const CopyIcon = createAnimatedIcon(BaseCopy, "CopyIcon");
export const CpuIcon = createAnimatedIcon(BaseCpu, "CpuIcon");
export const DownloadIcon = createAnimatedIcon(BaseDownload, "DownloadIcon");
export const ExternalLinkIcon = createAnimatedIcon(BaseExternalLink, "ExternalLinkIcon");
export const EyeIcon = createAnimatedIcon(BaseEye, "EyeIcon");
export const FileTextIcon = createAnimatedIcon(BaseFileText, "FileTextIcon");
export const FlaskIcon = createAnimatedIcon(BaseFlask, "FlaskIcon");
export const FolderGit2Icon = createAnimatedIcon(BaseFolderGit2, "FolderGit2Icon");
export const FolderOpenIcon = createAnimatedIcon(BaseFolderOpen, "FolderOpenIcon");
export const FolderSyncIcon = createAnimatedIcon(BaseFolderSync, "FolderSyncIcon");
export const GitBranchIcon = createAnimatedIcon(BaseGitBranch, "GitBranchIcon");
export const GitPullRequestIcon = createAnimatedIcon(BaseGitPullRequest, "GitPullRequestIcon");
export const HistoryIcon = createAnimatedIcon(BaseHistory, "HistoryIcon");
export const LayersIcon = createAnimatedIcon(BaseLayers, "LayersIcon");
export const LayoutPanelTopIcon = createAnimatedIcon(BaseLayoutPanelTop, "LayoutPanelTopIcon");
export const LockIcon = createAnimatedIcon(BaseLock, "LockIcon");
export const LogoutIcon = createAnimatedIcon(BaseLogout, "LogoutIcon");
export const Maximize2Icon = createAnimatedIcon(BaseMaximize2, "Maximize2Icon");
export const MenuIcon = createAnimatedIcon(BaseMenu, "MenuIcon");
export const MinimizeIcon = createAnimatedIcon(BaseMinimize, "MinimizeIcon");
export const MoonIcon = createAnimatedIcon(BaseMoon, "MoonIcon");
export const PlusIcon = createAnimatedIcon(BasePlus, "PlusIcon");
export const RefreshCWIcon = createAnimatedIcon(BaseRefreshCw, "RefreshCWIcon");
export const RotateCCWIcon = createAnimatedIcon(BaseRotateCcw, "RotateCCWIcon");
export const SearchIcon = createAnimatedIcon(BaseSearch, "SearchIcon");
export const ShieldCheckIcon = createAnimatedIcon(BaseShieldCheck, "ShieldCheckIcon");
export const SlidersHorizontalIcon = createAnimatedIcon(BaseSlidersHorizontal, "SlidersHorizontalIcon");
export const SparklesIcon = createAnimatedIcon(BaseSparkles, "SparklesIcon");
export const SunIcon = createAnimatedIcon(BaseSun, "SunIcon");
export const TerminalIcon = createAnimatedIcon(BaseTerminal, "TerminalIcon");
export const TrendingDownIcon = createAnimatedIcon(BaseTrendingDown, "TrendingDownIcon");
export const TrendingUpIcon = createAnimatedIcon(BaseTrendingUp, "TrendingUpIcon");
export const UploadIcon = createAnimatedIcon(BaseUpload, "UploadIcon");
export const WrenchIcon = createAnimatedIcon(BaseWrench, "WrenchIcon");
export const XIcon = createAnimatedIcon(BaseX, "XIcon");

// --- Drop-in Lucide Alias Equivalents ---
export const Activity = ActivityIcon;
export const ArrowLeft = ArrowLeftIcon;
export const ArrowRight = ArrowRightIcon;
export const ArrowUp = ArrowUpIcon;
export const ArrowUpRight = ArrowUpRightIcon;
export const BookOpen = BookTextIcon;
export const Check = CheckIcon;
export const CheckCircle2 = CircleCheckIcon;
export const ChevronDown = ChevronDownIcon;
export const ChevronRight = ChevronRightIcon;
export const Clock = ClockIcon;
export const Copy = CopyIcon;
export const Cpu = CpuIcon;
export const Download = DownloadIcon;
export const ExternalLink = ExternalLinkIcon;
export const Eye = EyeIcon;
export const FileText = FileTextIcon;
export const FlaskConical = FlaskIcon;
export const FolderGit2 = FolderGit2Icon;
export const FolderOpen = FolderOpenIcon;
export const FolderSync = FolderSyncIcon;
export const GitBranch = GitBranchIcon;
export const GitPullRequest = GitPullRequestIcon;
export const HelpCircle = CircleHelpIcon;
export const History = HistoryIcon;
export const Layers = LayersIcon;
export const LayoutDashboard = LayoutPanelTopIcon;
export const Lock = LockIcon;
export const LogOut = LogoutIcon;
export const Maximize2 = Maximize2Icon;
export const Menu = MenuIcon;
export const Minimize2 = MinimizeIcon;
export const Moon = MoonIcon;
export const Package = BoxIcon;
export const Plus = PlusIcon;
export const RefreshCw = RefreshCWIcon;
export const RotateCcw = RotateCCWIcon;
export const Search = SearchIcon;
export const ShieldCheck = ShieldCheckIcon;
export const Sliders = SlidersHorizontalIcon;
export const SlidersHorizontal = SlidersHorizontalIcon;
export const Sparkles = SparklesIcon;
export const Sun = SunIcon;
export const Terminal = TerminalIcon;
export const TrendingDown = TrendingDownIcon;
export const TrendingUp = TrendingUpIcon;
export const Upload = UploadIcon;
export const Wrench = WrenchIcon;
export const X = XIcon;
