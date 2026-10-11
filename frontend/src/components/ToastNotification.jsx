import React from 'react';
import { CheckCircle2, AlertTriangle, AlertCircle, Info, X } from 'lucide-react';
import './ToastNotification.css';

export default function ToastNotification({ toasts = [], onDismiss }) {
  if (!toasts.length) return null;

  return (
    <div className="toast-stack-container">
      {toasts.map((toast) => {
        const getIcon = () => {
          switch (toast.type) {
            case 'success': return <CheckCircle2 size={16} className="toast-icon text-success" />;
            case 'warning': return <AlertTriangle size={16} className="toast-icon text-warning" />;
            case 'error': return <AlertCircle size={16} className="toast-icon text-error" />;
            default: return <Info size={16} className="toast-icon text-info" />;
          }
        };

        return (
          <div key={toast.id} className={`toast-card toast-${toast.type} animate-fade-in`}>
            {getIcon()}
            <div className="toast-content">
              <span className="toast-title">{toast.title}</span>
              {toast.message && <p className="toast-message">{toast.message}</p>}
            </div>
            <button 
              className="toast-close-btn" 
              onClick={() => onDismiss && onDismiss(toast.id)}
            >
              <X size={14} />
            </button>
          </div>
        );
      })}
    </div>
  );
}
