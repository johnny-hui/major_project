import {navbarStyles} from "../NavBar/styles";


export const LayoutStyles = {
    root: {
        display: 'flex',
    },
    appBar: {
        width: `calc(100% - ${navbarStyles.drawer.width}px)`,
        marginLeft: navbarStyles.drawer.width,
        backgroundColor: '#151515',
    },
    appBarTopContent: {
        display: 'flex',
        height: 150,
        flexDirection: 'row',
        justifyContent: 'center'
    },
    appBarRightGrid: {
        display: 'flex', flexDirection: 'row', justifyContent: 'flex-end'
    },
    appBarAvatarBox: {
        mr: 6
    },
    avatar: {
        height: 56,
        width: 56,
        mr: 3
    },
    avatarName: {
        color: '#ECECEC',
        fontWeight: 'bold',
        fontSize: "16px",
        fontFamily: "Montserrat, sans-serif;"
    },
    avatarRole: {
        color: '#949494',
        fontFamily: "Montserrat, sans-serif;",
        fontSize: "13px"
    },
    avatarIP: {
        color: '#949494',
        fontFamily: "Montserrat, sans-serif;",
        fontSize: "13px"
    },
    page: {
        marginTop: '150px',
        width: '100%'
    },
    layoutTitle: {
        color: '#ECECEC',
        fontWeight: 'bold',
        fontFamily: "Montserrat, sans-serif;"
    },
    layoutDescription: {
        color: '#949494',
        fontFamily: "Montserrat, sans-serif;",
        fontSize: "18px"
    }
}