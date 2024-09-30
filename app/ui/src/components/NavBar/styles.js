export const navbarStyles = {
    divider: {
        borderRadius: 2,
        backgroundColor: '#36393D',
    },
    drawer: {
        width: 320,
        flexShrink: 0,
        '& .MuiDrawer-paper': {
            width: 320,
            backgroundColor: '#151515',
            borderColor: "transparent",
            color: 'rgba(255, 255, 255, 0.7)',
        },
        '& .Mui-selected': {
            color: 'red',
        },
    },
    icons: {
        color: 'white',
        marginLeft: '20px',
    },
    iconsBottom: {
        color: 'red',
        marginLeft: '20px',
    },
    text: {
        color: '#ECECEC',
        '& span': {
            marginLeft: '-10px',
            fontWeight: '600',
            fontSize: '16px',
            fontFamily: "Montserrat, sans-serif;"
        },
    },
    textBottom: {
        color: '#949494',
        '& span': {
            marginLeft: '-10px',
            fontWeight: '600',
            fontSize: '16px',
            fontFamily: "Montserrat, sans-serif;"
        },
    },
    logoBar: {
        height: '115px',
    },
    containerTextP2P: {
        display: "flex", flexDirection: "column", alignItems: "flex-start", justifyContent: "center",
    },
    containerTextApp: {
        display: "flex", flexDirection: "column", alignItems: "flex-start", justifyContent: "center",
    },
    P2P: {
        fontFamily: "Montserrat, sans-serif;",
        fontWeight: "bold",
        fontSize: "40px",
        color: '#ECECEC',
    },
    App: {
        fontFamily: "Kaushan Script, cursive",
        fontWeight: "bold",
        fontSize: "40px",
        color: "#FFCB21"
    }
};