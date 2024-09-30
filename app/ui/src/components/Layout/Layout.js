import {AppBar, Avatar, Box, Container, Grid, Typography} from "@mui/material";
import Toolbar from "@mui/material/Toolbar";
import NavDrawer from "../NavBar/NavDrawer";
import React from "react";
import {LayoutStyles} from "./styles";

export default function Layout({ children, location }) {
    return (
        <Container sx={LayoutStyles.root} maxWidth={false}>
            <AppBar
                position="fixed"
                elevation={0}
                sx={LayoutStyles.appBar}>
                <Toolbar sx={LayoutStyles.appBarTopContent}>
                    <Grid container spacing={2}>
                        <Grid item xs={6}>
                            {/* Only render if page is '/overview'*/}
                            {location.pathname === '/overview' && (
                              <Box sx={{ml: 6}}>
                                <Typography sx={LayoutStyles.layoutTitle} variant="h3">
                                  Welcome back, Bob
                                </Typography>
                              </Box>
                            )}
                        </Grid>
                        <Grid item sx={LayoutStyles.appBarRightGrid} xs={6}>
                            <Avatar sx={LayoutStyles.avatar} />
                            <Box sx={LayoutStyles.appBarAvatarBox}>
                                <Typography sx={LayoutStyles.avatarName}>
                                    Bob Ross
                                </Typography>
                                <Typography sx={LayoutStyles.avatarRole}>
                                    Role: Admin
                                </Typography>
                                <Typography sx={LayoutStyles.avatarIP}>
                                    127.0.0.1
                                </Typography>
                            </Box>
                        </Grid>
                        <Grid item xs={6}>
                            {/* Only render if page is '/overview'*/}
                            {location.pathname === '/overview' ? (
                                <Box sx={{ml: 6}}>
                                    <Typography sx={LayoutStyles.layoutDescription} variant="h10">
                                        Below is a summary of your local P2P network's activity
                                    </Typography>
                                </Box>
                            ) : (
                                <br></br>
                            )}
                        </Grid>
                    </Grid>
                </Toolbar>
            </AppBar>

            <NavDrawer/>

            {/* Main content */}
            <Container sx={LayoutStyles.page} maxWidth={false}>
                { children }
            </Container>
        </Container>
    )
}