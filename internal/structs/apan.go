package structs

import "time"

type ApanOtpModel struct {
	Mobile           string `json:"mobile"`
	TokenId          string `json:"TokenId"`
	Cif              string `json:"cif"`
	Pin              string `json:"pin"`
	Token            string `json:"token"`
	VerificationCode string `json:"verificationCode"`
}

type ApanApiRequestModel struct {
	Key        string `json:"Key"`
	Value      string `json:"Value"`
	DeviceInfo string `json:"DeviceInfo"`
}

type ApanResultFinalOtp struct {
	SecretKey          string `json:"secretKey"`
	OtpLen             string `json:"otpLen"`
	PeriodOtpSecondPin string `json:"periodOtpSecondPin"`
	ErrorCode          string `json:"ErrorCode"`
	ErrorString        string `json:"ErrorString"`
}

type ApanOtpData struct {
	SecretKey          string `json:"secretKey"`
	OtpLen             int    `json:"otpLen"`
	PeriodOtpSecondPin int    `json:"periodOtpSecondPin"`
}

type ApanLoginDeviceModel struct {
	MobileNumber     string  `json:"mobileNumber"`
	UserDeviceInfo   string  `json:"userDeviceInfo"`
	AppId            string  `json:"appId"`
	AppCode          string  `json:"appCode"`
	ActivationCode   string  `json:"activationCode"`
	AppControlTypeId int     `json:"appControlTypeId"`
	TokenId          *string `json:"tokenId"`
}

type ApanSubscriber struct {
	Address     *string   `json:"address"`
	BirthDate   time.Time `json:"birthDate"`
	Email       string    `json:"email"`
	FirstName   string    `json:"firstName"`
	Gender      byte      `json:"gender"`
	IsUpdated   bool      `json:"isUpdated"`
	LastName    string    `json:"lastName"`
	Mobile      string    `json:"mobile"`
	NidCity     int       `json:"nidCity"`
	NidProvince int       `json:"nidProvince"`
	TokenId     *string   `json:"tokenId"`
}

type MessageModel struct {
	ErrorCode   int         `json:"ErrorCode"`
	ErrorString string      `json:"ErrorString"`
	Ver         interface{} `json:"Ver"`
	Info        []struct {
		MobileNumber string      `json:"MobileNumber"`
		FirstName    string      `json:"FirstName"`
		LastName     string      `json:"LastName"`
		Gender       int         `json:"Gender"`
		BirthDate    string      `json:"BirthDate"`
		Address      interface{} `json:"Address"`
		Email        string      `json:"Email"`
		Score        int         `json:"Score"`
		NidProvince  int         `json:"NidProvince"`
		NidCity      int         `json:"NidCity"`
		CityName     string      `json:"CityName"`
		ProvinceName string      `json:"ProvinceName"`
	} `json:"Info"`
}

type DataModel struct {
	Data      string `json:"Data"`
	TokenID   string `json:"TokenId"`
	NewMacKey string `json:"NewMacKey"`
	NewPinKey string `json:"NewPinKey"`
	URL       string `json:"Url"`
	Info      []struct {
		HashID               interface{} `json:"HashId"`
		MobileNumber         string      `json:"MobileNumber"`
		IsCustomer           int         `json:"IsCustomer"`
		IsOrganizationMember int         `json:"IsOrganizationMember"`
		ENidCustomer         interface{} `json:"ENidCustomer"`
		CardNumber           interface{} `json:"CardNumber"`
		FirstName            string      `json:"FirstName"`
		LastName             string      `json:"LastName"`
		Gender               int         `json:"Gender"`
		BirthDate            string      `json:"BirthDate"`
		Address              interface{} `json:"Address"`
		Email                string      `json:"Email"`
		NidProvince          int         `json:"NidProvince"`
		NidCity              int         `json:"NidCity"`
		CityName             string      `json:"CityName"`
		ProvinceName         string      `json:"ProvinceName"`
	} `json:"Info"`
	CustomerAccounts []struct {
		Accounts interface{} `json:"Accounts"`
		Scores   interface{} `json:"Scores"`
	} `json:"CustomerAccounts"`
	Menu []struct {
		ENidService            string      `json:"ENidService"`
		ServiceID              int64       `json:"ServiceID"`
		MenuID                 int         `json:"MenuID"`
		SourceMenuID           interface{} `json:"SourceMenuID"`
		ParentMenuID           int         `json:"ParentMenuID"`
		ServiceTypeID          int         `json:"ServiceTypeID"`
		ServiceRouteID         int         `json:"ServiceRouteID"`
		ServiceTypeTitle       string      `json:"ServiceTypeTitle"`
		Title                  string      `json:"Title"`
		Description            string      `json:"Description"`
		Icon                   string      `json:"Icon"`
		URL                    interface{} `json:"Url"`
		AwardScore             int         `json:"AwardScore"`
		AwardScorePerUnitPrice int         `json:"AwardScorePerUnitPrice"`
		Controller             interface{} `json:"Controller"`
		Action                 interface{} `json:"Action"`
		IDHashMerchantTerminal interface{} `json:"IdHashMerchantTerminal"`
		Payable                bool        `json:"Payable"`
		Locations              []struct {
			IsAllProvinces bool        `json:"IsAllProvinces"`
			IsAllCIties    bool        `json:"IsAllCIties"`
			NidProvince    interface{} `json:"NidProvince"`
			NidCity        interface{} `json:"NidCity"`
		} `json:"Locations"`
	} `json:"Menu"`
}

type ApanSingleResponse struct {
	MessageModel []MessageModel `json:"MessageModel"`
	DataModel    []DataModel    `json:"DataModel"`
}

type ApanMultipleResponse []ApanSingleResponse

type ApanLogItem struct {
	AppId          int    `json:"appId"`
	Description    string `json:"description"`
	DeviceIp       string `json:"deviceIp"`
	LogTypeId      int    `json:"logTypeId"`
	Title          string `json:"title"`
	TokenId        string `json:"tokenId"`
	UserDeviceInfo string `json:"userDeviceInfo"`
}
