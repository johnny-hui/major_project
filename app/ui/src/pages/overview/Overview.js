import React from 'react';
import {Box, Grid} from "@mui/material";
import BlockchainDisplay from "../../components/Blockchain/BlockchainDisplay";


const Overview = () => {
    return (
      <Box sx={{ flexGrow: 2 }}>
        <Grid container spacing={2}>

          {/* Top Box: Spans full width */}
          <Grid item xs={12}>
            <Box>
              <BlockchainDisplay/>
            </Box>
          </Grid>

          {/* Bottom Left Box: Takes half the width */}
          <Grid item xs={12} md={6}>
            <Box sx={{
              backgroundColor: 'secondary.main',
              color: 'white',
              height: 200,
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center'
            }}>
              Left Box (Half Width)
            </Box>
          </Grid>

          {/* Bottom Right Box: Takes half the width */}
          <Grid item xs={12} md={6}>
            <Box sx={{
              backgroundColor: 'success.main',
              color: 'white',
              height: 200,
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center'
            }}>
              Right Box (Half Width)
            </Box>
          </Grid>
        </Grid>
      </Box>
    );
  }


export default Overview;