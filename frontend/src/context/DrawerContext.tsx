import React, { createContext, useContext, useState, useCallback, useRef } from 'react';

export interface DrawerOptions {
  title?: React.ReactNode;
  fullPageAction?: React.ReactNode;
}

export interface DrawerContextType {
  isOpen: boolean;
  content: React.ReactNode | null;
  options: DrawerOptions;
  open: (content: React.ReactNode, options?: DrawerOptions) => void;
  close: () => void;
  triggerRef: React.MutableRefObject<HTMLElement | null>;
  setTrigger: (el: HTMLElement | null) => void;
}

const DrawerContext = createContext<DrawerContextType | undefined>(undefined);

export const DrawerProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [content, setContent] = useState<React.ReactNode | null>(null);
  const [options, setOptions] = useState<DrawerOptions>({});
  const triggerRef = useRef<HTMLElement | null>(null);

  const setTrigger = useCallback((el: HTMLElement | null) => {
    triggerRef.current = el;
  }, []);

  const open = useCallback((newContent: React.ReactNode, newOptions: DrawerOptions = {}) => {
    if (!triggerRef.current && document.activeElement instanceof HTMLElement) {
      triggerRef.current = document.activeElement;
    }
    setContent(newContent);
    setOptions(newOptions);
    setIsOpen(true);
  }, []);

  const close = useCallback(() => {
    setIsOpen(false);
    setTimeout(() => {
      setContent(null);
      setOptions({});
      if (triggerRef.current && typeof triggerRef.current.focus === 'function') {
        triggerRef.current.focus();
        triggerRef.current = null;
      }
    }, 150);
  }, []);

  return (
    <DrawerContext.Provider value={{ isOpen, content, options, open, close, triggerRef, setTrigger }}>
      {children}
    </DrawerContext.Provider>
  );
};

export function useDrawer(): DrawerContextType {
  const ctx = useContext(DrawerContext);
  if (!ctx) {
    throw new Error('useDrawer must be used within a DrawerProvider');
  }
  return ctx;
}
