import React from 'react';
import {Box, Container, Grid, Skeleton, Typography} from '@mui/material';
import Block from "../Block/Block";
import {BlockchainDisplayStyles} from "./styles";
import Carousel from "react-material-ui-carousel";
import {chunkArray} from "./utility";

const BlockchainDisplay = ( {blockchain} ) => {
    const dummyArray = chunkArray([null, null, null, null], 4)

    return (
        <Container sx={BlockchainDisplayStyles.root} maxWidth={false}>
            <Typography sx={BlockchainDisplayStyles.title} variant="h4">Blockchain (Connection History)</Typography>
            {blockchain.length === 0 ? (
              <Carousel sx={BlockchainDisplayStyles.carousel} indicators={false}>
                {dummyArray.map((chunk, index) => (
                  <Box key={index}>
                    <Grid container spacing={3}>
                      {chunk.map((block, idx) => (
                        <Grid item xs={3} key={idx}>
                          <Skeleton
                            sx={{ backgroundColor: 'grey.900' }}
                            animation="wave" variant="rectangular"
                            width="100%" height="550px"
                          />
                        </Grid>
                      ))}
                    </Grid>
                  </Box>
                ))}
              </Carousel>
            ) : (
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
            )}
        </Container>
    );
};

export default BlockchainDisplay;
