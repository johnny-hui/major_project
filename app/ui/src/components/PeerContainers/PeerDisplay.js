import {
    Paper,
    styled,
    Table,
    TableBody,
    TableCell,
    tableCellClasses,
    TableContainer,
    TableHead,
    TableRow, Typography
} from "@mui/material";
import React from "react";
import {PeerDisplayStyles} from "./styles";

const StyledTableCell = styled(TableCell)(() => ({
  [`&.${tableCellClasses.head}`]: {
    backgroundColor: "#1B1B1B",
    color: '#949494',
    borderBottom: `1px solid #949494`
  },
  [`&.${tableCellClasses.body}`]: {
    fontFamily: "Montserrat, sans-serif;",
    fontSize: 14,
    color: '#949494',
    borderBottom: `1px solid #949494`, // Change this to your desired divider color
  },
}));

function createData(name, calories, fat, carbs, protein) {
  return { name, calories, fat, carbs, protein };
}

const PeerDisplay = ( {peerList} ) => {
    const rows = [
      createData('Frozen yoghurt', 159, 6.0, 24, 4.0),
      createData('Ice cream sandwich', 237, 9.0, 37, 4.3),
      createData('Eclair', 262, 16.0, 24, 6.0),
      createData('Cupcake', 305, 3.7, 67, 4.3),
      createData('Gingerbread', 356, 16.0, 49, 3.9),
    ];

    return (
        <TableContainer
            sx={{
                ...PeerDisplayStyles.currentPeerContainer.root,
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                height: '100%', // Make sure it takes the full height of the parent
            }}
            component={Paper}
        >
            {peerList.length === 0 ? (
                <Typography variant="h6" align="center" sx={{ padding: 2, fontFamily: "Montserrat, sans-serif;", color: "#949494" }}>
                    No data available
                </Typography>
            ) : (
                <Table stickyHeader sx={{ minWidth: 650 }} aria-label="customized table">
                    <TableHead sx={PeerDisplayStyles.currentPeerContainer.tableHead}>
                        <TableRow>
                            <StyledTableCell>Dessert (100g serving)</StyledTableCell>
                            <StyledTableCell align="right">Calories</StyledTableCell>
                            <StyledTableCell align="right">Fat&nbsp;(g)</StyledTableCell>
                            <StyledTableCell align="right">Carbs&nbsp;(g)</StyledTableCell>
                            <StyledTableCell align="right">Protein&nbsp;(g)</StyledTableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {rows.map((row) => (
                            <TableRow sx={PeerDisplayStyles.currentPeerContainer.tableRow} key={row.name}>
                                <StyledTableCell component="th" scope="row">
                                    {row.name}
                                </StyledTableCell>
                                <StyledTableCell align="right">{row.calories}</StyledTableCell>
                                <StyledTableCell align="right">{row.fat}</StyledTableCell>
                                <StyledTableCell align="right">{row.carbs}</StyledTableCell>
                                <StyledTableCell align="right">{row.protein}</StyledTableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            )}
        </TableContainer>
    );
}

export default PeerDisplay;
