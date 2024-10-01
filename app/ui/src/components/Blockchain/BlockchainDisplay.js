import React, {useEffect, useState} from 'react';
import {Alert, Box, Container, Grid, Snackbar, Typography} from '@mui/material';
import Block from "../Block/Block";
import {BlockchainDisplayStyles} from "./styles";
import {useSocket} from "../SocketContext/SocketContext";
import Carousel from "react-material-ui-carousel";
import {chunkArray} from "./utility";

const BlockchainDisplay = () => {
    const socket = useSocket();  // => access the socket instance from context
    const [blockchain, setBlockchain] = useState([]);
    const [open, setOpen] = useState(false);
    const [message, setMessage] = useState('');

    useEffect(() => {
        if (!socket) return;

        // Send fetch event to API server (when component mounts)
        socket.emit('request_blockchain_data');

        // Listen to events
        socket.on('blockchain_data', (data) => {
            if (data === "None") {
                setMessage("EVENT: Failed to receive any data!")
                setOpen(true)
            }
            else {
                setBlockchain(chunkArray(JSON.parse(data), 4)); // Update the blockchain state
                setMessage("EVENT: Received blockchain data!")
                setOpen(true)
            }
        });

        return () => {
            socket.off('blockchain_data');
        };
    }, [socket]);

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
            <Carousel sx={BlockchainDisplayStyles.carousel} indicators={false}>
                {blockchain.map((chunk, index) => (
                    <Box key={index}>
                      <Grid container spacing={3}>
                        {chunk.map((block, idx) => (
                          <Grid item xs={3} key={idx}>
                            <Block block={block} />
                          </Grid>
                        ))}
                      </Grid>
                    </Box>
                ))}
            </Carousel>
        </Container>
    );
};

export default BlockchainDisplay;
