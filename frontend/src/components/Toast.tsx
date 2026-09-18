import { useEffect, useState } from "react";
import { CheckCircle2, Info, X, XCircle } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import "./Toast.css";

export type ToastTone = "info" | "success" | "error";

interface ToastItem {
  id: number;
  message: string;
  tone: ToastTone;
}

const DISMISS_AFTER_MS = 4000;

// Module-level event bus rather than a React context: this is a single-page
// app with exactly one ToastHost near the root, so a Provider wrapping the
// tree buys nothing over a shared array + subscriber set, and it lets
// useToast() work from anywhere without requiring callers to sit under a
// <ToastProvider>.
let toasts: ToastItem[] = [];
let nextId = 0;
const listeners = new Set<(items: ToastItem[]) => void>();

function emit() {
  for (const listener of listeners) listener(toasts);
}

function dismiss(id: number) {
  toasts = toasts.filter((t) => t.id !== id);
  emit();
}

function push(message: string, tone: ToastTone = "info") {
  const id = nextId++;
  toasts = [...toasts, { id, message, tone }];
  emit();
  setTimeout(() => dismiss(id), DISMISS_AFTER_MS);
}

export function useToast() {
  return { push };
}

const TONE_ICON: Record<ToastTone, LucideIcon> = {
  info: Info,
  success: CheckCircle2,
  error: XCircle,
};

/** Renders queued toasts, stacked bottom-right. Mount once near app root. */
export function ToastHost() {
  const [items, setItems] = useState<ToastItem[]>(toasts);

  useEffect(() => {
    listeners.add(setItems);
    return () => {
      listeners.delete(setItems);
    };
  }, []);

  return (
    <div className="toast-host" aria-live="polite" aria-atomic="false">
      {items.map((item) => {
        const Icon = TONE_ICON[item.tone];
        return (
          <div key={item.id} className="toast" data-tone={item.tone} role="status">
            <Icon className="toast__icon" aria-hidden="true" size={16} />
            <span className="toast__message">{item.message}</span>
            <button
              type="button"
              className="toast__close"
              aria-label="Dismiss notification"
              onClick={() => dismiss(item.id)}
            >
              <X size={14} />
            </button>
          </div>
        );
      })}
    </div>
  );
}
