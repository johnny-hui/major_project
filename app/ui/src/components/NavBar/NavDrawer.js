import React from 'react';
import Drawer from '@mui/material/Drawer';
import Toolbar from '@mui/material/Toolbar';
import List from '@mui/material/List';
import Divider from '@mui/material/Divider';
import ListItem from '@mui/material/ListItem';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import CloudOffTwoToneIcon from '@mui/icons-material/CloudOffTwoTone';
import {mainNavbarItems} from "./constants";
import {navbarStyles} from "./styles";
import {useNavigate} from "react-router-dom";
import logo from "../../logos/app_logo_no_bg.png"
import {Grid, Typography} from "@mui/material";


const NavDrawer = () => {
    const navigate = useNavigate();

    return (
      <Drawer
        sx={navbarStyles.drawer}
        variant="permanent"
        anchor="left"
      >
            <Toolbar sx={navbarStyles.logoBar}>
                <Grid container>
                    <Grid item xs={4}>
                        <img style={{width: 80, height: 80}} src={logo} alt="P2P Logo"/>
                    </Grid>
                    <Grid sx={navbarStyles.containerTextP2P} item xs={4}>
                        <Typography sx={navbarStyles.P2P}>P2P</Typography>
                    </Grid>
                    <Grid sx={navbarStyles.containerTextApp} item xs={4}>
                        <Typography sx={navbarStyles.App} variant="h3">App</Typography>
                    </Grid>
                </Grid>
            </Toolbar>
          <Divider sx={navbarStyles.divider}/>
          <List>
              {mainNavbarItems.map((item) => (
                <ListItem
                    button
                    key={item.id}
                    onClick={() => navigate(item.route)}
                    disablePadding
                >
                  <ListItemButton>
                    <ListItemIcon sx={navbarStyles.icons}>
                      {item.icon}
                    </ListItemIcon>
                    <ListItemText
                        sx={navbarStyles.text}
                        primary={item.label} />
                  </ListItemButton>
                </ListItem>
              ))}
            </List>
            <Divider sx={navbarStyles.divider} />
            <List>
              {['Disconnect'].map((text) => (
                <ListItem key={text} disablePadding>
                  <ListItemButton>
                    <ListItemIcon sx={navbarStyles.iconsBottom}>
                      <CloudOffTwoToneIcon/>
                    </ListItemIcon>
                    <ListItemText sx={navbarStyles.textBottom} primary={text} />
                  </ListItemButton>
                </ListItem>
              ))}
            </List>
      </Drawer>
    );
}

export default NavDrawer;