"use client";

import { cn } from "@/lib/utils";
import Link, { LinkProps } from "next/link";
import React, { useState, createContext, useContext } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Menu, X } from "lucide-react";

export interface SidebarLinkItem {
  label: string;
  href?: string;
  icon: React.ReactNode;
  onClick?: () => void;
  active?: boolean;
  badge?: React.ReactNode;
}

interface SidebarContextProps {
  open: boolean;
  setOpen: React.Dispatch<React.SetStateAction<boolean>>;
  animate: boolean;
}

const SidebarContext = createContext<SidebarContextProps | undefined>(
  undefined
);

export const useSidebar = () => {
  const context = useContext(SidebarContext);
  if (!context) {
    throw new Error("useSidebar must be used within a SidebarProvider");
  }
  return context;
};

export const SidebarProvider = ({
  children,
  open: openProp,
  setOpen: setOpenProp,
  animate = true,
}: {
  children: React.ReactNode;
  open?: boolean;
  setOpen?: React.Dispatch<React.SetStateAction<boolean>>;
  animate?: boolean;
}) => {
  const [openState, setOpenState] = useState(false);

  const open = openProp !== undefined ? openProp : openState;
  const setOpen = setOpenProp !== undefined ? setOpenProp : setOpenState;

  return (
    <SidebarContext.Provider value={{ open, setOpen, animate }}>
      {children}
    </SidebarContext.Provider>
  );
};

export const Sidebar = ({
  children,
  open,
  setOpen,
  animate = true,
}: {
  children: React.ReactNode;
  open?: boolean;
  setOpen?: React.Dispatch<React.SetStateAction<boolean>>;
  animate?: boolean;
}) => {
  return (
    <SidebarProvider open={open} setOpen={setOpen} animate={animate}>
      {children}
    </SidebarProvider>
  );
};

export const SidebarBody = (props: React.ComponentProps<typeof motion.div>) => {
  return (
    <>
      <DesktopSidebar {...props} />
      <MobileSidebar {...(props as any)} />
    </>
  );
};

export const DesktopSidebar = ({
  className,
  children,
  ...props
}: React.ComponentProps<typeof motion.div>) => {
  const { open, setOpen, animate } = useSidebar();
  return (
    <motion.aside
      className={cn(
        "h-screen sticky top-0 px-3 py-6 hidden md:flex md:flex-col justify-between flex-shrink-0 z-30 transition-colors select-none",
        className
      )}
      style={{
        background: "var(--surface)",
        borderRight: "1px solid var(--line)",
      }}
      animate={{
        width: animate ? (open ? "240px" : "68px") : "240px",
      }}
      transition={{
        duration: 0.22,
        ease: [0.25, 1, 0.5, 1],
      }}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      {...(props as any)}
    >
      {children}
    </motion.aside>
  );
};

export const MobileSidebar = ({
  className,
  children,
  ...props
}: React.ComponentProps<"div">) => {
  const { open, setOpen } = useSidebar();
  return (
    <div className="md:hidden">
      <AnimatePresence>
        {open && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 0.5 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black/60 z-40 backdrop-blur-xs"
              onClick={() => setOpen(false)}
            />
            <motion.aside
              initial={{ x: "-100%" }}
              animate={{ x: 0 }}
              exit={{ x: "-100%" }}
              transition={{
                duration: 0.25,
                ease: "easeInOut",
              }}
              className={cn(
                "fixed top-0 bottom-0 left-0 w-[260px] p-6 z-50 flex flex-col justify-between shadow-2xl",
                className
              )}
              style={{
                background: "var(--surface)",
                borderRight: "1px solid var(--line)",
              }}
            >
              <button
                type="button"
                className="absolute right-4 top-4 p-2 text-neutral-400 hover:text-neutral-200 transition-colors"
                onClick={() => setOpen(false)}
                aria-label="Close menu"
              >
                <X size={18} />
              </button>
              {children}
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </div>
  );
};

export const SidebarLink = ({
  link,
  className,
}: {
  link: SidebarLinkItem;
  className?: string;
}) => {
  const { open, animate } = useSidebar();

  const content = (
    <>
      <div className="flex-shrink-0 flex items-center justify-center w-5 h-5 relative">
        {link.icon}
        {/* If collapsed and has a badge, show miniature dot on icon */}
        {!open && link.badge && (
          <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-[var(--accent)] ring-2 ring-[var(--surface)]" />
        )}
      </div>
      <motion.span
        animate={{
          display: animate ? (open ? "inline-flex" : "none") : "inline-flex",
          opacity: animate ? (open ? 1 : 0) : 1,
        }}
        transition={{ duration: 0.15 }}
        className="text-xs font-medium tracking-tight whitespace-nowrap overflow-hidden items-center justify-between flex-1 ml-3.5"
      >
        <span className="truncate">{link.label}</span>
        {link.badge}
      </motion.span>
    </>
  );

  const baseClass = cn(
    "flex items-center w-full px-3 py-2.5 rounded-md text-xs transition-all duration-150 cursor-pointer relative group",
    link.active
      ? "bg-[var(--accent-soft)] text-[var(--accent)] font-semibold"
      : "text-[var(--muted)] hover:bg-[var(--subtle)] hover:text-[var(--foreground)]",
    className
  );

  if (link.onClick) {
    return (
      <button
        type="button"
        onClick={link.onClick}
        className={baseClass}
        title={!open ? link.label : undefined}
      >
        {content}
      </button>
    );
  }

  return (
    <Link
      href={link.href || "#"}
      className={baseClass}
      title={!open ? link.label : undefined}
    >
      {content}
    </Link>
  );
};

