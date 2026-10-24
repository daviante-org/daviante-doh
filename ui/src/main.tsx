import React from 'react';
import ReactDOM from 'react-dom/client';
import '@patternfly/react-core/dist/styles/base.css';
import './app/index.css';
import { App } from './app';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Root DOM node #root was not found.');
}

ReactDOM.createRoot(rootElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
