// src/App.js

import React, {useEffect, useState} from 'react';
import {Container} from '@mui/material';
import {Outlet, useLocation} from "react-router-dom";
import Layout from "./components/Layout/Layout";
import {io} from "socket.io-client";
import {SocketProvider} from "./components/SocketContext/SocketContext";
import './App.css';

// Establish socket connection to backend
const socket = io('http://127.0.0.1:5000');

const App = () => {
    const [profileData, setProfileData] = useState(null);
    const location = useLocation()

    useEffect(() => {
        if (!socket) return;

        socket.on('init_data', (data) => {
            setProfileData(JSON.parse(data));
        });

        return () => {
            socket.off('init_data');
        };
    }, []);

    return (
        <SocketProvider socket={socket}>
            <Container sx={{backgroundColor: '#151515', height: "100vh"}} maxWidth={false}>
                <Layout location={location} profileData={profileData}>
                   <Outlet />
                </Layout>
            </Container>
        </SocketProvider>
    );
};

export default App;
