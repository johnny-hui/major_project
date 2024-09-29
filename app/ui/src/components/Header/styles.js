export const headerStyles = {
    wrapper: {
        display: 'block',
        flexDirection: 'column',
        backgroundColor: '#009be5',
        padding: '20px',
    },
    end: {
        display: 'flex',
        flexDirection: 'row',
        justifyContent: 'end',
        alignItems: 'center',
        backgroundColor: 'black',
    },
    start: {
        display: 'flex',
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        backgroundColor: "blue"
    },
    link: {
        fontWeight: 500,
        color: 'rgba(255, 255, 255, 0.7)',
        "&:hover": {
            color: '#fff',
            cursor: 'pointer',
        },
    },
    avatar: {
        width: 56,
        height: 56,
    }
};