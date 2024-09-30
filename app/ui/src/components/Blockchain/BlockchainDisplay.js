import React, {useEffect, useState} from 'react';
import {io} from 'socket.io-client';
import {Alert, Container, Snackbar, Typography} from '@mui/material';
import Block from "../Block/Block";
import {BlockchainDisplayStyles} from "./styles";

const socket = io('http://127.0.0.1:5000'); // Adjust the port if necessary

const BlockchainDisplay = () => {
    const [blockchain, setBlockchain] = useState([]);
    const [open, setOpen] = useState(false);
    const [message, setMessage] = useState('');

    useEffect(() => {
        // Send fetch event to API server
        socket.on('blockchain_data', (data) => {
            if (data === "None") {
                setMessage("EVENT: Failed to receive any data!")
                setOpen(true)
            }
            else {
                setBlockchain(JSON.parse(data)); // Update the blockchain state
                setMessage("EVENT: Received initialization data!")
                setOpen(true)
            }
        });
        return () => {
            socket.off('blockchain_data');
        };
    }, []);

    return (
        <Container sx={BlockchainDisplayStyles.root} maxWidth={false}>
            <Snackbar
                open={open}
                autoHideDuration={6000}
                onClose={() => setOpen(false)}
                anchorOrigin={{
                  vertical: "top",
                  horizontal: "right"
               }}>
                <Alert
                    onClose={() => setOpen(false)}
                    severity="success"
                    variant="filled"
                    sx={{ width: '100%' }}>
                    {message}
                </Alert>
            </Snackbar>
            <Typography sx={BlockchainDisplayStyles.title} variant="h4">Blockchain (Connection History)</Typography>
            {blockchain.map((block) => (
                <Block block={block}/>
            ))}
        </Container>
    );
};

export default BlockchainDisplay;
