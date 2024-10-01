import BarChartIcon from '@mui/icons-material/BarChart';
import ConnectWithoutContactIcon from '@mui/icons-material/ConnectWithoutContact';
import WidgetsIcon from '@mui/icons-material/Widgets';
import RequestPageIcon from '@mui/icons-material/RequestPage';

export const mainNavbarItems = [
    {
        id: 0,
        icon: <BarChartIcon color="primary"/>,
        label: 'Overview',
        route: 'overview',
    },
    {
        id: 1,
        icon: <RequestPageIcon color="secondary"/>,
        label: 'Connection Requests',
        route: 'requests',
    },
    {
        id: 2,
        icon: <WidgetsIcon sx={{color: "#ED7100"}}/>,
        label: 'Blockchain Demo',
        route: 'demo',
    },
    {
        id: 3,
        icon: <ConnectWithoutContactIcon color="success"/>,
        label: 'Connect to a P2P Network',
        route: 'connect',
    },
]
