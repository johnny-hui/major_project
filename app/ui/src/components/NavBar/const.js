import BarChartIcon from '@mui/icons-material/BarChart';
import ConnectWithoutContactIcon from '@mui/icons-material/ConnectWithoutContact';
import WidgetsIcon from '@mui/icons-material/Widgets';
import RequestPageIcon from '@mui/icons-material/RequestPage';

export const mainNavbarItems = [
    {
        id: 0,
        icon: <BarChartIcon />,
        label: 'Overview',
        route: 'overview',
    },
    {
        id: 1,
        icon: <RequestPageIcon />,
        label: 'Connection Requests',
        route: 'requests',
    },
    {
        id: 2,
        icon: <WidgetsIcon />,
        label: 'Blockchain Demo',
        route: 'demo',
    },
    {
        id: 3,
        icon: <ConnectWithoutContactIcon />,
        label: 'Connect to a P2P Network',
        route: 'connect',
    },
]
