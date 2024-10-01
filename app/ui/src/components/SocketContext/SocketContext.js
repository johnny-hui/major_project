// SocketContext.js
import React, { createContext, useContext } from 'react';
const SocketContext = createContext(null);

export const SocketProvider = ({ socket, children }) => {
    return (
        <SocketContext.Provider value={socket}>
            {children}
        </SocketContext.Provider>
    );
};

// Create a custom hook to easily access the socket instance
export const useSocket = () => {
    return useContext(SocketContext);
};