import React from 'react';
import {Box, Grid, Typography} from "@mui/material";
import BlockchainDisplay from "../../components/Blockchain/BlockchainDisplay";
import {OverviewStyles} from "./styles";


const Overview = () => {
  return (
    <Box sx={OverviewStyles.root}>
      <Grid container spacing={5}>

        {/* Top Box: Spans full width */}
        <Grid item xs={12}>
          <Box>
            <BlockchainDisplay/>
          </Box>
        </Grid>

        {/* Bottom Left Box: Takes half the width */}
        <Grid item xs={12} md={6}>
          <Box sx={OverviewStyles.bottomLeftBox}>
            <Typography sx={OverviewStyles.bottomLeftBox.title} variant="h5">
              Current Peers
            </Typography>
          </Box>
        </Grid>

        {/* Bottom Right Box: Takes half the width */}
        <Grid item xs={12} md={6}>
          <Box sx={OverviewStyles.bottomRightBox}>
            <Typography sx={OverviewStyles.bottomRightBox.title} variant="h5">
              Pending Peers
            </Typography>
          </Box>
        </Grid>
      </Grid>
    </Box>
  );
}

export default Overview;