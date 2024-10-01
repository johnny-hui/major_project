import {
    Box,
    Button,
    Card,
    CardActionArea,
    CardActions,
    CardContent,
    CardMedia,
    Collapse,
    Typography
} from "@mui/material";
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import {useState} from "react";
import defaultAvatar from "../../images/default_avatar.png"
import {blockStyles} from "./styles";
import {getFieldMappings} from "./FieldMappings";


export default function Block({ block }) {
  const [expanded, setExpanded] = useState(false);
  const fieldMappings = getFieldMappings();

  const handleExpandClick = () => {
    setExpanded(!expanded);
  };

    return (
      <Card sx={ blockStyles.root }>
        <CardActionArea>
          <CardMedia
              sx={blockStyles.blockPicture}
              component="img"
              height="300"
              image={block.index === 0 ? `${defaultAvatar}` : `data:image/jpeg;base64,${block.image}`}
          />
          <CardContent sx={{ borderBottom: "1px solid lightgray"}}>
            <Typography sx={ blockStyles.blockTitle } gutterBottom variant="h5" component="div">
              {block.index === 0 ? "Genesis Block" : block.first_name + " " + block.last_name}
            </Typography>
            <Typography sx={ blockStyles.blockIndex } variant="body1">
              Block {block.index}
            </Typography>
          </CardContent>
        </CardActionArea>
        <CardActions sx={ blockStyles.blockDropdownContainer }>
          <Button
              size="small"
              onClick={handleExpandClick}
              aria-expanded={expanded}
              aria-label="show more">
            <ExpandMoreIcon />
          </Button>
        </CardActions>
        <Collapse sx={ blockStyles.collapseStyle } in={expanded} unmountOnExit>
        <CardContent sx={{ display: 'block', paddingLeft: 3, paddingRight: 3, marginTop: -3 }}>
          {fieldMappings.map(({ key, label, style }, index) => (
            <Box key={key} sx={{ marginBottom: index === fieldMappings.length - 1 ? 0 : 2 }}>
              <Typography sx={blockStyles.blockInfoFieldTitle} variant="h6">
                {label}
              </Typography>
              <Typography sx={style}>
                {block[key] === null ? 'None' : block[key]}
              </Typography>
            </Box>
          ))}
        </CardContent>
        </Collapse>
      </Card>
    )
}