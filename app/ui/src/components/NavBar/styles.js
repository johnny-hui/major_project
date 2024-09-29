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
            boxSizing: 'border-box',
            backgroundColor: '#151515',
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
    text: {
        color: '#CDCDCD',
        '& span': {
            marginLeft: '-10px',
            fontWeight: '600',
            fontSize: '16px',
        }
    },
    toolbar: {
        height: '115px'
    }
};