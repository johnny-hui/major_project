import React, {useEffect, useState} from 'react';
import {Box, Grid, Typography} from "@mui/material";
import BlockchainDisplay from "../../components/Blockchain/BlockchainDisplay";
import {OverviewStyles} from "./styles";
import {useSocket} from "../../components/SocketContext/SocketContext";
import {chunkArray} from "../../components/Blockchain/utility";
import SnackbarNotification from "../../components/SnackbarNotification/SnackbarNotification";
import PeerDisplay from "../../components/PeerContainers/PeerDisplay";


const Overview = () => {
    const socket = useSocket();  // => access the socket instance from context
    const [blockchain, setBlockchain] = useState([]);
    const [currentPeers, setCurrentPeers] = useState([]);
    const [pendingPeers, setPendingPeers] = useState([]);
    const [open, setOpen] = useState(false);
    const [message, setMessage] = useState('');
    const [severity, setSeverity] = useState("");
    const [alertTitle, setAlertTitle] = useState("");

    useEffect(() => {
        if (!socket) return;
        document.title = 'P2P App | Overview';

        // a) Request overview data upon component mount
        socket.emit('request_blockchain_data')

        // b) Listen to real-time events from backend
        socket.on('blockchain_data', (data) => {  // => EVENT: receive blockchain
            if (data === "None") {
                setAlertTitle("WARNING")
                setMessage("No blockchain data has been found")
                setSeverity("warning")
                setOpen(true)
            }
            else {
                setBlockchain(chunkArray(JSON.parse(data), 4));
                setAlertTitle("SUCCESS")
                setMessage("Successfully received blockchain data!")
                setSeverity("success")
                setOpen(true)
            }
        });

        socket.on('new_approved_peer', (newPeer) => {  // => EVENT: receive a new approved peer
            setCurrentPeers(prevPeers => [...prevPeers, newPeer]);
            setAlertTitle("SUCCESS")
            setMessage(`A new peer has successfully joined the network (${newPeer.ip})`)
            setSeverity("success")
            setOpen(true)
        });

        socket.on('remove_approved_peer', (ip) => {  // => EVENT: remove an approved peer
            setCurrentPeers(prevPeers => prevPeers.filter(peer => peer.ip !== ip));
            setAlertTitle("SUCCESS")
            setMessage(`The following connected peer has been removed! (IP: ${ip})`)
            setSeverity("success")
            setOpen(true)
        });

        socket.on('new_pending_peer', (newPeer) => {  // => EVENT: receive a new pending peer
            setPendingPeers(prevPeers => [...prevPeers, newPeer]);
            setAlertTitle("SUCCESS")
            setMessage("A new pending peer has been added!")
            setSeverity("success")
            setOpen(true)
        });

        socket.on('remove_pending_peer', (ip) => {  // => EVENT: remove a new pending peer
            setPendingPeers(prevPeers => prevPeers.filter(peer => peer.ip !== ip));
            setAlertTitle("SUCCESS")
            setMessage(`The following pending peer has been removed! (IP: ${ip})`)
            setSeverity("success")
            setOpen(true)
        });

        socket.on('add_block', (newBlock) => {  // => EVENT: receive a new block
            if (newBlock === "None" || !newBlock) {
                setAlertTitle("ERROR")
                setMessage("An error has occurred while receiving a new block from the back-end!");
                setSeverity("error")
                setOpen(true);
            } else {
                try {
                    const parsedBlock = JSON.parse(newBlock);
                    setBlockchain((prevBlockchain) => {
                        // transform current blockchain into a single array
                        const flatBlockchain = prevBlockchain.flat();

                        // add new block at end of blockchain
                        const updatedBlockchain = [...flatBlockchain, parsedBlock];

                        // re-chunk the array into groups of fours
                        return chunkArray(updatedBlockchain, 4);
                    });
                    setAlertTitle("SUCCESS")
                    setMessage("EVENT: A new block has been added to the blockchain!");
                    setSeverity("success")
                    setOpen(true);
                } catch (error) {
                    setAlertTitle("ERROR")
                    setMessage("EVENT: An error occurred while processing the new block!");
                    setSeverity("error")
                    setOpen(true);
                }
            }
        });
        return () => {
            socket.off('blockchain_data');
            socket.off('add_block');
            socket.off('new_pending_peer');
            socket.off('remove_pending_peer');
            socket.off('new_approved_peer');
            socket.off('remove_approved_peer');
        };
    }, [socket]);

  return (
    <Box sx={OverviewStyles.root}>
        <SnackbarNotification
            open={open}
            onClose={() => setOpen(false)}
            severity={severity}
            alertTitle={alertTitle}
            message={message}
        />

        <Grid container spacing={5}>
            {/* Top Box: Spans full width */}
            <Grid item xs={12}>
              <Box>
                <BlockchainDisplay blockchain={blockchain} />
              </Box>
            </Grid>

            {/* Bottom Left Box: Takes half the width */}
            <Grid item xs={12} md={6}>
              <Box sx={OverviewStyles.bottomLeftBox}>
                  <Typography sx={OverviewStyles.bottomLeftBox.title} variant="h4">
                    Current Peers
                  </Typography>
                  <PeerDisplay peerList={currentPeers} />
              </Box>
            </Grid>

            {/* Bottom Right Box: Takes half the width */}
            <Grid item xs={12} md={6}>
              <Box sx={OverviewStyles.bottomRightBox}>
                <Typography sx={OverviewStyles.bottomRightBox.title} variant="h4">
                  Pending Peers
                </Typography>
                <PeerDisplay peerList={pendingPeers} />
              </Box>
            </Grid>
        </Grid>
    </Box>
  );
}

export default Overview;