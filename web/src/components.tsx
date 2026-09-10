import { useEffect, useRef } from "react";
import type { ReactNode } from "react";
import { X, AlertTriangle, LoaderCircle } from "lucide-react";
export function Modal({
  title,
  children,
  onClose,
  wide = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    ref.current?.showModal();
    const d = ref.current;
    return () => d?.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className={wide ? "modal wide" : "modal"}
      onCancel={onClose}
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
      aria-labelledby="modal-title"
    >
      <div className="modal-head">
        <h2 id="modal-title">{title}</h2>
        <button
          onClick={onClose}
          className="icon-button"
          aria-label="Close dialog"
        >
          <X size={18} />
        </button>
      </div>
      <div className="modal-content">{children}</div>
    </dialog>
  );
}
export function ErrorNotice({ children }: { children: ReactNode }) {
  return (
    <div role="alert" className="notice error">
      <AlertTriangle size={16} />
      <span>{children}</span>
    </div>
  );
}
export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <LoaderCircle className="spin" size={18} />
      {label}
    </div>
  );
}
export function Empty({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-mark">∅</div>
      <h2>{title}</h2>
      <div>{children}</div>
    </div>
  );
}
export function Status({ value }: { value: unknown }) {
  const text = typeof value === "string" ? value : "Unknown";
  const kind =
    /^(ok|healthy|connected|online|receiving|listening|complete|completed|allow|success|parsed)$/i.test(
      text,
    )
      ? "good"
      : /^(fail|failed|error|offline|emergency|critical|deny|drop|blocked)$/i.test(
            text,
          )
        ? "bad"
        : "neutral";
  return (
    <span className={`status ${kind}`}>
      <i />
      {text.replaceAll("_", " ")}
    </span>
  );
}
