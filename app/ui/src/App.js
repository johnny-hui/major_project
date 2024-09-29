// src/App.js

import React from 'react';
import {Grid} from '@mui/material';
import {Outlet} from "react-router-dom";
import Layout from "./components/Layout/Layout";


const App = () => {
    return (
        <Grid container sx={{backgroundColor: '#151515'}}>
            <Layout>
               <Outlet/>
            </Layout>
        </Grid>
    );
};

export default App;
