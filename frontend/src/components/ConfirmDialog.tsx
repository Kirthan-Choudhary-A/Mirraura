import { useEffect, useRef } from "react";
import type { ReactNode } from "react";
import "./ConfirmDialog.css";

/**
 * Wraps a native <dialog> — showModal()/close() driven by the `open` prop,
 * so Esc-to-cancel and focus-return-on-close come from the platform for
 * free instead of a hand-rolled backdrop/focus-trap.
 */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      dialog.showModal();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  return (
    <dialog
      ref={dialogRef}
      className="confirm-dialog"
      onCancel={(e) => {
        // Esc fires "cancel" then "close". Route it through our onCancel
        // callback (which the caller uses to flip `open` to false) rather
        // than letting the dialog close itself out of band.
        e.preventDefault();
        onCancel();
      }}
      onClick={(e) => {
        if (e.target === dialogRef.current) onCancel();
      }}
    >
      <h2 className="confirm-dialog__title">{title}</h2>
      <div className="confirm-dialog__description">{description}</div>
      <div className="confirm-dialog__actions">
        <button type="button" className="confirm-dialog__cancel" onClick={onCancel}>
          Cancel
        </button>
        <button type="button" className="confirm-dialog__confirm" onClick={onConfirm}>
          {confirmLabel}
        </button>
      </div>
    </dialog>
  );
}
