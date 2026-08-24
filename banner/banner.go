package banner

import (
	"fmt"
)

// prints the version message
const version = "v0.0.2"

func PrintVersion() {
	fmt.Printf("Current ffufscan version %s\n", version)
}

// Prints the Colorful banner
func PrintBanner() {
	banner := `                                        
    ____ ____        ____                        
   / __// __/__  __ / __/_____ _____ ____ _ ____ 
  / /_ / /_ / / / // /_ / ___// ___// __  // __ \
 / __// __// /_/ // __/(__  )/ /__ / /_/ // / / /
/_/  /_/   \__,_//_/  /____/ \___/ \__,_//_/ /_/
`
	fmt.Printf("%s\n%50s\n\n", banner, "Current ffufscan version "+version)
}
