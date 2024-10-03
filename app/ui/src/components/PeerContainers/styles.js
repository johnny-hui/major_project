export const PeerDisplayStyles = {
    currentPeerContainer: {
        root: {
            maxHeight: 260,
            marginTop: 3,
            '&::-webkit-scrollbar': {
              display: 'none',  // => hide scroll bar
            },
            scrollbarWidth: 'none',
            borderRadius: '6px',
            boxShadow: '0 3px 10px rgba(0, 0, 0, 0.1)',
            backgroundColor: '#151515',
        },
        tableHead: {
            '& th': {
                fontFamily: "Montserrat, sans-serif;",
                fontWeight: 'bold',
                fontSize: '1.1rem',
            },
        },
        tableRow: {
            backgroundColor: "#1B1B1B",
            '&:last-child td, &:last-child th': {  // => hide last border
                border: 0,
            },
            '&:hover': {
                backgroundColor: '#151515',
            },
        },
    },
}