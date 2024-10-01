import React, {Component} from 'react';
import {Typography} from "@mui/material";

class NotFound extends Component {
    render() {
        return (
            <div style={{color: 'white', marginLeft: '500px', marginTop: '125px',}}>
                <Typography>Error 404: Page Not Found!</Typography>
            </div>
        );
    }
}

export default NotFound;