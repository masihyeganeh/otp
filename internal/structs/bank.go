package structs

type Bank struct {
	ID           string   `json:"id"`
	Phone        string   `json:"phone"`
	URL          string   `json:"url"`
	PublicKey    string   `json:"publicKey"`
	Certificates []string `json:"certificates"`
}
