import {Avatar, Box, Typography} from "@mui/material";
import {headerStyles} from "./styles";

const Header = ( {title} ) => {
    return (
        <Box sx={headerStyles.wrapper}>
            <Box>
                <Typography variant="h3" color="white">
                    {title}
                </Typography>
            </Box>
            <Box>
                <Avatar sx={headerStyles.avatar} src="https://mui.com/static/images/avatar/1.jpg" />
                <Typography sx={headerStyles.link}>
                    Go to docs
                </Typography>
            </Box>
        </Box>
    )
}

export default Header