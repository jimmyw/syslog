import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";

const style = document.createElement("style");
style.textContent = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html, body, #root { height: 100%; background: #000; }
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: #000; }
  ::-webkit-scrollbar-thumb { background: #2c2c2e; border-radius: 3px; }
  select option { background: #1c1c1e; }
`;
document.head.appendChild(style);

createRoot(document.getElementById("root")).render(
  <StrictMode><App /></StrictMode>
);
