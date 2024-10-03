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

const PeerDisplay = ( {peerList} ) => {
    return (
        <TableContainer
            sx={peerList.length === 0 ? PeerDisplayStyles.peerContainer.noData : PeerDisplayStyles.peerContainer.root}
            component={Paper}
        >
            {peerList.length === 0 ? (
                <Typography variant="h6" align="center" sx={{ padding: 2, fontFamily: "Montserrat, sans-serif;", color: "#949494" }}>
                    No data available
                </Typography>
            ) : (
                <Table stickyHeader aria-label="customized table">
                    <TableHead sx={PeerDisplayStyles.peerContainer.tableHead}>
                        <TableRow>
                            <StyledTableCell>IP</StyledTableCell>
                            <StyledTableCell>First Name</StyledTableCell>
                            <StyledTableCell>Last Name</StyledTableCell>
                            <StyledTableCell>Role</StyledTableCell>
                            <StyledTableCell>Status</StyledTableCell>
                            <StyledTableCell>Secret</StyledTableCell>
                            <StyledTableCell>Initialization Factor (IV)</StyledTableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {peerList.map((peer) => (
                            <TableRow sx={PeerDisplayStyles.peerContainer.tableRow} key={peer.ip}>
                                <StyledTableCell>
                                    {peer.ip}
                                </StyledTableCell>
                                <StyledTableCell>{peer.first_name}</StyledTableCell>
                                <StyledTableCell>{peer.last_name}</StyledTableCell>
                                <StyledTableCell>{peer.role}</StyledTableCell>
                                <StyledTableCell>{peer.status}</StyledTableCell>
                                <StyledTableCell sx={PeerDisplayStyles.peerContainer.tableCell}>
                                    {peer.secret}
                                </StyledTableCell>
                                <StyledTableCell sx={PeerDisplayStyles.peerContainer.tableCell}>
                                    {peer.iv}
                                </StyledTableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            )}
        </TableContainer>
    );
}

export default PeerDisplay;
