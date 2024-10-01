export const blockStyles = {
    root: {
        position: 'relative',
        backgroundColor: '#ECECEC',
        borderRadius: '16px',
        overflow: 'visible',
        boxShadow: '0 4px 10px rgba(0, 0, 0, 0.2)',
        width: '100%',
        '&::after': {
            content: '""',
            position: 'absolute',
            top: '100%', // Position it below the card
            left: 0,
            right: 0,
            height: '15px',
            background: 'linear-gradient(40deg, rgba(255, 255, 255, 0.3), rgba(255, 195, 0, 0))',
            borderRadius: '0 0 16px 16px',
            zIndex: -1, // Place behind the card
            filter: 'blur(8px)',
        },

        '&:hover': {
            transform: 'translateY(-5px)',
            boxShadow: '0 8px 20px rgba(0, 0, 0, 0.3)',
            backgroundColor: 'white',
            '&::after': {
                background: 'linear-gradient(180deg, rgba(255, 255, 255, 1), rgba(255, 195, 0, 0))',
            },
        },
    },
    collapseStyle: {
        overflow: 'auto',
        maxHeight: 150,
        '&::-webkit-scrollbar': {
            width: '6px',
            height: '6px',
        },
        '&::-webkit-scrollbar-track': {
            backgroundColor: 'transparent',
        },
        '&::-webkit-scrollbar-thumb': {
            backgroundColor: '#888',
            borderRadius: '10px',
        },
        '&::-webkit-scrollbar-thumb:hover': {
            backgroundColor: '#555',
        },
    },
    blockPicture: {
        borderTopLeftRadius: '16px',
        borderTopRightRadius: '16px'
    },
    blockTitle: {
        color: '#949494', fontFamily: "Montserrat, sans-serif;",
        textAlign: "center", fontWeight: "bold"
    },
    blockIndex: {
        color: '#949494', fontFamily: "Montserrat, sans-serif;",
        textAlign: "center", fontStyle: 'italic'
    },
    blockDropdownContainer: {
        justifyContent: 'center'
    },
    blockInfoFieldTitle: {
        fontFamily: "Montserrat, sans-serif;",
        fontWeight: "bold"
    },
    blockInfoHash: {
        fontFamily: "Montserrat, sans-serif;",
        fontSize: '14px',
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        color: '#ba000d'
    },
    blockInfoText: {
        fontFamily: "Montserrat, sans-serif;",
        fontSize: '14px',
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        color: 'gray'
    },
    blockInfoSignature: {
        fontFamily: "Montserrat, sans-serif;",
        fontSize: '14px',
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        color: '#757ce8'
    }
}