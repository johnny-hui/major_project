import {navbarStyles} from "../NavBar/styles";


export const LayoutStyles = {
    appBar: {
        height: 150,
        width: `calc(100% - ${navbarStyles.drawer.width}px)`,
        marginLeft: navbarStyles.drawer.width,
    },
    page: {
        marginTop: '150px',
        width: '100%'
    },
    root: {
        display: 'flex',
    },
    active: {
        background: '#f4f4f4'
    },
}