// SnackbarNotification.js

import React from 'react';
import { Alert, AlertTitle, Snackbar } from "@mui/material";

const SnackbarNotification = ({ open, onClose, severity, alertTitle, message }) => {
    return (
        <Snackbar
            open={open}
            autoHideDuration={6000}
            onClose={onClose}
            anchorOrigin={{
                vertical: "top",
                horizontal: "right"
            }}
        >
            <Alert
                onClose={onClose}
                severity={severity}
                variant="filled"
                sx={{ width: '100%' }}
            >
                <AlertTitle>{alertTitle}</AlertTitle>
                {message}
            </Alert>
        </Snackbar>
    );
};

export default SnackbarNotification;