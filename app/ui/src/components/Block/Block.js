import {Card, CardHeader} from "@mui/material";

export default function Block({ block }) {
    return (
        <div className="block">
            <Card key={block.index}>
                <CardHeader
                    title={"Block " + block.index}
                    subheader={block.timestamp}
                />
            </Card>
        </div>
    )
}