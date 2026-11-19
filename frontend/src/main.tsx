import React from "react";
import { createRoot } from "react-dom/client";

import "./style.css";
import App from "./App";

const container = document.querySelector("#root");
if (!container) {
  throw new Error("Missing #root element in index.html");
}

const root = createRoot(container);

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
