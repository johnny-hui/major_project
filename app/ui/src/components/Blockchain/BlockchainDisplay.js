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

        // Listen to events from backend
        socket.on('blockchain_data', (data) => {  // => EVENT: receive blockchain
            if (data === "None") {
                setMessage("EVENT: No blockchain is present on the back-end!")
                setOpen(true)
            }
            else {
                setBlockchain(chunkArray(JSON.parse(data), 4)); // Update the blockchain state
                setMessage("EVENT: Successfully received blockchain data!")
                setOpen(true)
            }
        });
        socket.on('add_block', (newBlock) => {
            if (newBlock === "None" || !newBlock) {
                setMessage("EVENT: An error has occurred while receiving a new block from the back-end!");
                setOpen(true);
            } else {
                try {
                    // Parse the new block if it's a JSON string
                    const parsedBlock = JSON.parse(newBlock);

                    setBlockchain((prevBlockchain) => {
                        // Flatten the current chunked blockchain into a single array
                        const flatBlockchain = prevBlockchain.flat();

                        // Append the parsed block to the flattened blockchain
                        const updatedBlockchain = [...flatBlockchain, parsedBlock];

                        // Chunk the updated blockchain back into groups of 4 blocks
                        const chunkedBlockchain = chunkArray(updatedBlockchain, 4);

                        // Log to see the chunked blockchain
                        console.log("Updated chunked blockchain:", chunkedBlockchain);

                        // Return the new chunked blockchain
                        return chunkedBlockchain;
                    });

                    setMessage("EVENT: A new block has been added to the blockchain!");
                    setOpen(true);
                } catch (error) {
                    setMessage("EVENT: An error occurred while processing the new block!");
                    setOpen(true);
                }
            }
        });

        return () => {
            socket.off('blockchain_data');
            socket.off('add_block');
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
