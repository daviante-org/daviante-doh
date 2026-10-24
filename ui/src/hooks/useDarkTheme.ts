import { useEffect, useState } from 'react';

export function useDarkTheme() {
  const [isDarkTheme, setIsDarkTheme] = useState<boolean>(() =>
    document.documentElement.classList.contains('pf-v6-theme-dark')
  );

  useEffect(() => {
    const root = document.documentElement;
    if (isDarkTheme) {
      root.classList.add('pf-v6-theme-dark');
    } else {
      root.classList.remove('pf-v6-theme-dark');
    }
  }, [isDarkTheme]);

  return { isDarkTheme, setIsDarkTheme };
}
