// src/App.js

import React from 'react';
import {Container} from '@mui/material';
import {Outlet, useLocation} from "react-router-dom";
import Layout from "./components/Layout/Layout";
import './App.css';

const App = () => {
    const location = useLocation()

    return (
        <Container sx={{backgroundColor: '#151515', height: "100vh"}} maxWidth={false}>
            <Layout location={location}>
               <Outlet/>
            </Layout>
        </Container>
    );
};

export default App;
