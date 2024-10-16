import React from 'react';
import ReactDOM from 'react-dom/client'; // Updated import
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';
import {BrowserRouter, Routes, Route, Navigate} from "react-router-dom";
import Overview from "./pages/overview/Overview";
import BlockchainDemo from "./pages/demo/BlockchainDemo";
import ConnectionRequests from "./pages/requests/ConnectionRequests";
import ConnectToNetwork from "./pages/connect/ConnectToNetwork";
import NotFound from "./pages/notfound/NotFound";

// Create a root container and render the app
const root = ReactDOM.createRoot(document.getElementById('root')); // Updated root creation
root.render(
  <BrowserRouter>
    <Routes>
        <Route path="/" element={<App />}>
            {/* Redirects root "/" to "/overview" */}
            <Route index element={<Navigate to="/overview" replace />} />
            <Route path="overview" element={<Overview />} />
            <Route path="requests" element={<ConnectionRequests />} />
            <Route path="demo" element={<BlockchainDemo />} />
            <Route path="connect" element={<ConnectToNetwork />} />
            {/* Catch-all route for undefined URLs */}
            <Route path="*" element={<NotFound />} />
        </Route>
    </Routes>
  </BrowserRouter>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
