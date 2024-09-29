import {AppBar, Container, Typography} from "@mui/material";
import Toolbar from "@mui/material/Toolbar";
import NavDrawer from "../NavBar/NavDrawer";
import React from "react";
import {LayoutStyles} from "./styles";

export default function Layout({ children }) {
    return (
        <Container sx={LayoutStyles.root}>
            <AppBar
                position="fixed"
                elevation={0}
                color="primary"
                sx={LayoutStyles.appBar}
            >
                <Toolbar>
                  <Typography>
                    Testing
                  </Typography>
                  <Typography>
                      Mario
                  </Typography>
                </Toolbar>
            </AppBar>

            <NavDrawer/>

            {/* Main content */}
            <Container sx={LayoutStyles.page}>
                { children }
            </Container>
        </Container>
    )
}