import React from 'react';
import Drawer from '@mui/material/Drawer';
import Toolbar from '@mui/material/Toolbar';
import List from '@mui/material/List';
import Divider from '@mui/material/Divider';
import ListItem from '@mui/material/ListItem';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import InboxIcon from '@mui/icons-material/MoveToInbox';
import MailIcon from '@mui/icons-material/Mail';
import {mainNavbarItems} from "./const";
import {navbarStyles} from "./styles";
import {useNavigate} from "react-router-dom";

const NavDrawer = () => {
    const navigate = useNavigate();

    return (
      <Drawer
        sx={navbarStyles.drawer}
        variant="permanent"
        anchor="left"
      >
            <Toolbar sx={navbarStyles.toolbar}/>
            <Divider sx={navbarStyles.divider} />
            <List>
              {mainNavbarItems.map((item, index) => (
                <ListItem
                    button
                    key={item.id}
                    onClick={() => navigate(item.route)}
                    disablePadding
                >
                  <ListItemButton>
                    <ListItemIcon
                        sx={navbarStyles.icons}
                    >
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
              {['All mail', 'Trash', 'Spam'].map((text, index) => (
                <ListItem key={text} disablePadding>
                  <ListItemButton>
                    <ListItemIcon>
                      {index % 2 === 0 ? <InboxIcon /> : <MailIcon />}
                    </ListItemIcon>
                    <ListItemText primary={text} />
                  </ListItemButton>
                </ListItem>
              ))}
            </List>
      </Drawer>
    );
}

export default NavDrawer;